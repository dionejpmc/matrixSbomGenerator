from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sbom', '0010_component_cpe_sbomupload_rejection_reason_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='component',
            name='supplier',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='copyright',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='author',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='depends',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='folder',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='component',
            name='scope',
            field=models.CharField(
                blank=True,
                choices=[('third_party', 'Terceiros'), ('first_party', 'Primeira parte')],
                default='third_party',
                max_length=20,
            ),
        ),
    ]