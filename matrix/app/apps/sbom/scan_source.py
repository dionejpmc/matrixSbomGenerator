"""
Scanner de código-fonte para pré-preenchimento de SBOM (Matrix SBOM Manager).

Endpoint: POST /sbom/api/scan/source/
    multipart: files[] (arquivos), paths[] (caminhos relativos), base_path (opcional)
    resposta:  {"components": [ {name, version, type, purl, cpe, supplier,
                                 license, copyright, author, description,
                                 depends, folder, scope, origin,
                                 duplicate, duplicate_group}, ... ]}

Princípio central: TODO dado reportado vem do arquivo. O scanner não inventa
fornecedor, purl, cpe nem versão. Campos que o arquivo não declara ficam
vazios, para o analista preencher na revisão.

Camadas de detecção:
  1. Assinaturas conhecidas (mbedTLS, FreeRTOS, lwIP, ...): usadas APENAS para
     detectar presença e extrair a versão da própria lib (via macro no
     arquivo). Não geram supplier/purl/cpe — esses são deixados vazios.
  2. Macros genéricas  #define XYZ_VERSION "1.0.0".
  3. Cabeçalho de documentação (Doxygen): \\file, \\version, \\author,
     \\brief, \\note, \\copyright, \\license — lidos sob qualquer estilo de
     comentário (///, //, /* */, #, ; , @).

Nome do componente-arquivo: COM extensão (ADC.c, ADC.h são distintos). O
caminho completo com o arquivo (ex.: proj/src/ADC.c) fica no campo `folder`.

Duplicidade: arquivos de primeira parte com o mesmo nome (mas caminhos
diferentes) NÃO são fundidos. Ambos aparecem, marcados com duplicate=True e um
duplicate_group comum, para o analista decidir qual manter.

Registro de URL (urls.py do app sbom):
    path("api/scan/source/", scan_source.api_scan_source, name="api_scan_source"),
"""

import re
from dataclasses import dataclass, field, asdict

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_POST

MAX_FILE_BYTES = getattr(settings, "SCAN_MAX_FILE_BYTES", 5 * 1024 * 1024)
MAX_FILES_PER_REQUEST = getattr(settings, "SCAN_MAX_FILES_PER_REQUEST", 100000)


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

@dataclass
class Component:
    name: str
    version: str = ""
    type: str = "library"
    purl: str = ""
    cpe: str = ""
    supplier: str = ""
    license: str = ""
    copyright: str = ""
    author: str = ""
    description: str = ""
    depends: str = ""
    folder: str = ""
    scope: str = "third_party"       # third_party | first_party
    origin: str = "auto"
    duplicate: bool = False          # nome repetido em caminho diferente
    duplicate_group: str = ""        # chave do grupo de duplicidade (o nome)
    # interno: True quando o arquivo escaneado pertence ao componente
    # (a versão/identidade foi definida ali) -> herda metadados do cabeçalho
    _owns_file: bool = False

    def to_dict(self):
        d = asdict(self)
        d.pop("_owns_file", None)
        return d


# ---------------------------------------------------------------------------
# Assinaturas de bibliotecas conhecidas
#
# Servem SOMENTE para (a) detectar que a lib está presente e (b) extrair a
# versão dela a partir de macros do próprio arquivo. NÃO carregam supplier,
# purl ou cpe — nada que não venha do arquivo é inventado. O `name` é apenas
# um rótulo de reconhecimento.
# ---------------------------------------------------------------------------

@dataclass
class Signature:
    name: str
    presence: list = field(default_factory=list)
    version_patterns: list = field(default_factory=list)
    # padrão de #include que identifica esta lib como dependência
    include_pattern: str = ""

    def __post_init__(self):
        self._presence = [re.compile(p, re.IGNORECASE) for p in self.presence]
        self._versions = [re.compile(p) for p in self.version_patterns]
        self._include = re.compile(self.include_pattern, re.IGNORECASE) if self.include_pattern else None


SIGNATURES = [
    Signature(
        name="FreeRTOS",
        presence=[r'#\s*include\s*["<](FreeRTOS|FreeRTOSConfig|task|queue|semphr)\.h[">]', r"\bFreeRTOS\b"],
        version_patterns=[
            r'tskKERNEL_VERSION_NUMBER\s+"V?([\d]+(?:\.[\d]+)*)"',
            r"FreeRTOS\s+Kernel\s+V([\d]+(?:\.[\d]+)*)",
            r"FreeRTOS\s+V([\d]+(?:\.[\d]+)*)",
        ],
        include_pattern=r"^(FreeRTOS|FreeRTOSConfig|task|queue|semphr|timers|event_groups)\.h$",
    ),
    Signature(
        name="mbedTLS",
        presence=[r'#\s*include\s*["<]mbedtls/', r"\bMBEDTLS_[A-Z0-9_]+\b", r"\bmbed\s*TLS\b"],
        version_patterns=[
            r'MBEDTLS_VERSION_STRING(?:_FULL)?\s+"(?:mbed\s*TLS\s+)?([\d]+(?:\.[\d]+)*)"',
            r"mbed\s*TLS\s+v?([\d]+\.[\d]+\.[\d]+)",
        ],
        include_pattern=r"^mbedtls/",
    ),
    Signature(
        name="lwIP",
        presence=[r'#\s*include\s*["<]lwip/', r"\bLWIP_[A-Z0-9_]+\b", r"\blwIP\b"],
        version_patterns=[r'LWIP_VERSION_STRING\s+"([\d]+(?:\.[\d]+)*)"', r"lwIP\s+v?([\d]+\.[\d]+\.[\d]+)"],
        include_pattern=r"^lwip/",
    ),
    Signature(
        name="zlib",
        presence=[r'#\s*include\s*["<]zlib\.h[">]', r"\bZLIB_VERSION\b"],
        version_patterns=[r'ZLIB_VERSION\s+"([\d]+(?:\.[\d]+)*)"'],
        include_pattern=r"^zlib\.h$",
    ),
    Signature(
        name="cJSON",
        presence=[r'#\s*include\s*["<]cJSON\.h[">]', r"\bCJSON_VERSION_MAJOR\b"],
        version_patterns=[],
        include_pattern=r"^cJSON\.h$",
    ),
    Signature(
        name="FatFs",
        presence=[r'#\s*include\s*["<]ff\.h[">]', r"\bFatFs\b", r"\bFF_DEFINED\b"],
        version_patterns=[r"FatFs.*?R([\d]+\.[\d]+[a-z]?)"],
        include_pattern=r"^ff\.h$",
    ),
]

MULTIPART_VERSION = {
    "lwIP": ("LWIP_VERSION_MAJOR", "LWIP_VERSION_MINOR", "LWIP_VERSION_REVISION"),
    "cJSON": ("CJSON_VERSION_MAJOR", "CJSON_VERSION_MINOR", "CJSON_VERSION_PATCH"),
    "FreeRTOS": ("tskKERNEL_VERSION_MAJOR", "tskKERNEL_VERSION_MINOR", "tskKERNEL_VERSION_BUILD"),
}

KNOWN_PREFIXES = {"MBEDTLS", "LWIP", "ZLIB", "CJSON", "FREERTOS", "TSKKERNEL"}

GENERIC_VERSION_RE = re.compile(
    r'#\s*define\s+([A-Za-z][A-Za-z0-9_]*?)_(?:VERSION|VERSION_STRING|VER)\s+"v?([\d]+(?:\.[\d]+)*)"'
)
INCLUDE_RE = re.compile(r'#\s*include\s*[<"]([^">]+)[">]')


# ---------------------------------------------------------------------------
# Cabeçalho de documentação (Doxygen) sob qualquer estilo de comentário
#
# Estilos suportados de prefixo de comentário de LINHA:
#   //  ///  //!  //<   (C/C++/Go/Rust/JS)
#   #                   (Python, Make, CMake, YAML, shell, alguns asm)
#   ;                   (assembly de vários montadores, INI)
#   @                   (assembly ARM/GAS)  — cuidado: só quando seguido de tag
# Estilos de BLOCO: /* ... */  e  /** ... */  (linhas internas com '*')
#
# Regra anti-#define / anti-código: uma linha só é tratada como portadora de
# tag Doxygen quando, após remover o prefixo de comentário, sobra "\tag" ou
# "@tag". '#define APP_VERSION' não casa (não há '\'/'@' após o '#').
# ---------------------------------------------------------------------------

# Remove o prefixo de comentário do início da linha.
#  - //, ///, //!, //<
#  - /*, /**, /*!, */, *
#  - # (um ou mais)
#  - ; (um ou mais)
# O '@' NÃO é removido como prefixo de comentário aqui, porque em C/asm o '@'
# inicia a tag; ver _DOX_TAG_RE que aceita linha começando por '@'.
_COMMENT_PREFIX_RE = re.compile(r"^\s*(?:/{2,}[<!]?|/\*+[!]?|\*+/|\*+|#+|;+)\s?")

# Tag Doxygen: \palavra ou @palavra no início do conteúdo já sem prefixo.
_DOX_TAG_RE = re.compile(r"^[\\@]([A-Za-z]+)\b\s*(.*)$")

# Marcadores que indicam início de um comentário de linha (para delimitar o
# bloco de cabeçalho no topo do arquivo).
_LINE_COMMENT_START = ("//", "#", ";")


def _strip_prefix(raw: str) -> str:
    return _COMMENT_PREFIX_RE.sub("", raw).strip()


def _is_line_comment(s: str) -> bool:
    return s.startswith(_LINE_COMMENT_START)


def _first_comment_block(text: str) -> str:
    """Retorna o bloco de comentário do topo do arquivo (o cabeçalho), parando
    no primeiro código real. Suporta bloco (/* */) e linha (//, ///, #, ;).
    Réguas (//////, ######) são mantidas mas não encerram o bloco."""
    lines = []
    started = False
    mode = None  # "block" | "line"

    for raw in text.splitlines():
        s = raw.strip()

        if not started:
            if not s:
                continue  # linhas em branco antes do cabeçalho
            if s.startswith("/*"):
                started, mode = True, "block"
                lines.append(raw)
                if "*/" in s[2:]:
                    break
                continue
            if _is_line_comment(s):
                started, mode = True, "line"
                lines.append(raw)
                continue
            return ""  # começa com código: sem cabeçalho

        if mode == "block":
            lines.append(raw)
            if "*/" in s:
                break
        else:  # linha: segue enquanto for comentário de linha ou linha vazia
            if _is_line_comment(s) or not s:
                lines.append(raw)
            else:
                break

    return "\n".join(lines)


def _collect_tags(header: str) -> dict:
    """Lê as tags Doxygen do cabeçalho, tolerando continuação de linhas."""
    fields: dict[str, list] = {}
    current = None
    for raw in header.splitlines():
        line = _strip_prefix(raw)
        m = _DOX_TAG_RE.match(line)
        if m:
            tag = m.group(1).lower()
            current = tag
            fields.setdefault(tag, [])
            if m.group(2).strip():
                fields[tag].append(m.group(2).strip())
        elif current and line:
            fields[current].append(line)  # continuação da tag anterior
        else:
            current = None
    return fields


# ---------------------------------------------------------------------------
# Licença / copyright (extraídos do arquivo, não inventados)
# ---------------------------------------------------------------------------

SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\- ()]+)")
COPYRIGHT_RE = re.compile(r"(Copyright\s*(?:\(c\)|©)?\s*[\d,\-\s]*[^\r\n]*)", re.IGNORECASE)


def parse_header_meta(text: str) -> dict:
    """Extrai version/author/description/license/copyright do cabeçalho.
    Nada é inferido de fora do arquivo: se a tag não existe, o campo fica
    vazio (a única exceção é o SPDX-License-Identifier, que é um identificador
    literal presente no próprio arquivo)."""
    header = _first_comment_block(text)
    fields = _collect_tags(header)

    def get(*tags):
        for t in tags:
            if fields.get(t):
                return " ".join(fields[t]).strip()
        return ""

    brief, note = get("brief"), get("note")
    description = " — ".join(p for p in (brief, note) if p)

    # versão do cabeçalho: \version 1.0.1  (vazio se ausente)
    version = ""
    vm = re.match(r"v?([\d]+(?:\.[\d]+)*)", get("version"))
    if vm:
        version = vm.group(1)

    # licença: SPDX literal no arquivo > tag \license/\spdx (texto do arquivo)
    license_id = ""
    m = SPDX_RE.search(text[:4096])
    if m:
        license_id = m.group(1).strip()
    else:
        license_id = get("license", "spdx")

    # copyright: tag \copyright, ou linha "Copyright ..." no cabeçalho
    copyright_txt = get("copyright")
    if not copyright_txt:
        m = COPYRIGHT_RE.search(header)
        copyright_txt = m.group(1).strip().rstrip("*/ ").strip() if m else ""

    return {
        "version": version,
        "author": get("author"),
        "description": description,
        "license": license_id,
        "copyright": copyright_txt,
    }


# ---------------------------------------------------------------------------
# Decodificação (legado embarcado costuma ser cp1252/latin-1)
# ---------------------------------------------------------------------------

def decode_source(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None  # binário
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Includes (dependências cruas) e utilitários
# ---------------------------------------------------------------------------

def extract_includes(text: str) -> str:
    """Todos os #include na ordem, sem duplicatas, como escritos."""
    headers = []
    for m in INCLUDE_RE.finditer(text):
        header = m.group(1).strip()
        if header and header not in headers:
            headers.append(header)
    return ", ".join(headers)


def _pretty_name(prefix: str) -> str:
    parts = re.split(r"[_\-]+", prefix)
    return "".join(p.capitalize() for p in parts if p)


def _multipart_version(text: str, macros) -> str:
    values = []
    for macro in macros:
        m = re.search(rf"#\s*define\s+{macro}\s+(\d+)", text)
        if not m:
            return ""
        values.append(m.group(1))
    return ".".join(values)


# ---------------------------------------------------------------------------
# Scan de um arquivo
# ---------------------------------------------------------------------------

def scan_file(rel_path: str, data: bytes, folder: str, emit_first_party: bool = True) -> list[Component]:
    text = decode_source(data)
    if text is None:
        return []

    file_name = rel_path.replace("\\", "/").split("/")[-1]
    found: list[Component] = []
    matched = set()

    # 1) assinaturas conhecidas: presença + versão (da macro do arquivo).
    #    Sem supplier/purl/cpe — nada inventado.
    for sig in SIGNATURES:
        if not any(p.search(text) for p in sig._presence):
            continue
        version = ""
        for vp in sig._versions:
            m = vp.search(text)
            if m:
                version = m.group(1)
                break
        if not version and sig.name in MULTIPART_VERSION:
            version = _multipart_version(text, MULTIPART_VERSION[sig.name])
        found.append(Component(
            name=sig.name, version=version,
            folder=folder, scope="third_party", _owns_file=bool(version),
        ))
        matched.add(sig.name.upper())

    # 2) macros genéricas *_VERSION "x.y.z" (o arquivo define -> pertence a ele)
    for m in GENERIC_VERSION_RE.finditer(text):
        prefix, version = m.group(1), m.group(2)
        if prefix.upper() in KNOWN_PREFIXES or prefix.upper() in matched:
            continue
        found.append(Component(
            name=_pretty_name(prefix), version=version,
            folder=folder, scope="first_party", _owns_file=True,
        ))
        matched.add(prefix.upper())

    # metadados do cabeçalho (inclui \version do arquivo)
    meta = parse_header_meta(text)
    depends = extract_includes(text)
    has_meta = any(meta[k] for k in ("version", "author", "description", "license", "copyright"))

    # 3) arquivo de primeira parte: quando nada de terceiros "dono" foi
    #    detectado, o próprio arquivo vira um componente type=file. Nome COM
    #    extensão (ADC.c e ADC.h são arquivos distintos — não são duplicidade);
    #    caminho completo no folder. A versão vem do \version do cabeçalho
    #    (vazia se ausente).
    owns_any = any(c._owns_file for c in found)
    if emit_first_party and not owns_any and (has_meta or True):
        found.append(Component(
            name=file_name,
            version=meta["version"],
            type="file",
            folder=folder,
            scope="first_party",
            _owns_file=True,
        ))

    # atribui metadados do cabeçalho aos componentes "donos" do arquivo
    for comp in found:
        if comp._owns_file:
            comp.version = comp.version or meta["version"]
            comp.author = comp.author or meta["author"]
            comp.description = comp.description or meta["description"]
            comp.license = comp.license or meta["license"]
            comp.copyright = comp.copyright or meta["copyright"]
            comp.depends = comp.depends or depends

    return found


# ---------------------------------------------------------------------------
# Consolidação do lote
#
# - Terceiros (scope=third_party): deduplicam por (name, version); a lib
#   espalhada por vários arquivos vira uma linha só, preferindo a versionada.
# - Arquivos de primeira parte (type=file): NUNCA se fundem — cada caminho é
#   um componente. Quando dois compartilham o mesmo nome (caminhos distintos),
#   ambos ficam marcados como duplicados para o analista decidir.
# ---------------------------------------------------------------------------

def consolidate(components: list[Component]) -> list[Component]:
    third_party = [c for c in components if c.type != "file"]
    files = [c for c in components if c.type == "file"]

    # --- terceiros: dedup por (nome, versão) ---
    by_key: dict[tuple, Component] = {}
    for comp in third_party:
        key = (comp.name.lower(), comp.version)
        if key not in by_key:
            by_key[key] = comp
        else:
            kept = by_key[key]
            if comp._owns_file and not kept._owns_file:
                by_key[key] = comp
            else:
                for attr in ("license", "copyright", "author", "description", "depends", "purl", "cpe", "supplier"):
                    if not getattr(kept, attr) and getattr(comp, attr):
                        setattr(kept, attr, getattr(comp, attr))
    versioned = {name for (name, ver) in by_key if ver}
    third_final = [c for (name, ver), c in by_key.items() if ver or name not in versioned]

    # --- arquivos de primeira parte: manter todos, deduplicando só caminho
    #     idêntico (mesmo arquivo enviado 2x). Marcar nomes repetidos. ---
    seen_paths = set()
    files_unique = []
    for c in files:
        path_key = (c.name.lower(), c.folder)
        if path_key in seen_paths:
            continue  # exatamente o mesmo arquivo/caminho: ignora repetição
        seen_paths.add(path_key)
        files_unique.append(c)

    # marca duplicidade de NOME (caminhos diferentes)
    name_counts: dict[str, int] = {}
    for c in files_unique:
        name_counts[c.name.lower()] = name_counts.get(c.name.lower(), 0) + 1
    for c in files_unique:
        if name_counts[c.name.lower()] > 1:
            c.duplicate = True
            c.duplicate_group = c.name

    # ordenação: primeira parte primeiro; duplicados agrupados pelo nome
    scope_order = {"first_party": 0, "third_party": 1}
    final = files_unique + third_final
    return sorted(final, key=lambda c: (scope_order.get(c.scope, 2), c.name.lower(), c.folder))


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

@require_POST
def api_scan_source(request):
    uploaded = request.FILES.getlist("files")
    if not uploaded:
        return JsonResponse({"components": []})
    if len(uploaded) > MAX_FILES_PER_REQUEST:
        return JsonResponse(
            {"error": f"Máximo de {MAX_FILES_PER_REQUEST} arquivos por lote. Envie em partes."},
            status=400,
        )

    paths = request.POST.getlist("paths")
    base_path = (request.POST.get("base_path") or "").strip()

    all_components: list[Component] = []
    for index, up in enumerate(uploaded):
        rel_path = paths[index] if index < len(paths) and paths[index] else up.name
        folder = _full_folder(rel_path, base_path)
        if up.size > MAX_FILE_BYTES:
            continue
        all_components.extend(scan_file(rel_path, up.read(), folder))

    result = consolidate(all_components)
    return JsonResponse({"components": [c.to_dict() for c in result]})


def _full_folder(rel_path: str, base_path: str) -> str:
    if not base_path:
        return rel_path
    sep = "\\" if "\\" in base_path else "/"
    rel = rel_path.replace("/", sep).replace("\\", sep)
    return base_path.rstrip("/\\") + sep + rel