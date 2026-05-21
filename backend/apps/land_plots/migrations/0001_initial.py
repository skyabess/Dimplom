import uuid

import django.contrib.gis.db.models.fields
import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LandCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='Category Name')),
                ('code', models.CharField(max_length=10, unique=True, verbose_name='Category Code')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Description')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
            ],
            options={'db_table': 'land_categories'},
        ),
        migrations.CreateModel(
            name='LandPurpose',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='Purpose Name')),
                ('code', models.CharField(max_length=10, unique=True, verbose_name='Purpose Code')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Description')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
            ],
            options={'db_table': 'land_purposes'},
        ),
        migrations.CreateModel(
            name='Region',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='Region Name')),
                ('code', models.CharField(max_length=10, unique=True, verbose_name='Region Code')),
                ('okato_code', models.CharField(max_length=15, unique=True, verbose_name='OKATO Code')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
            ],
            options={'db_table': 'regions'},
        ),
        migrations.CreateModel(
            name='District',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='District Name')),
                ('code', models.CharField(max_length=10, verbose_name='District Code')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
                ('region', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='districts', to='land_plots.region')),
            ],
            options={'db_table': 'districts', 'unique_together': {('region', 'code')}},
        ),
        migrations.CreateModel(
            name='Settlement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Settlement Name')),
                ('type', models.CharField(max_length=50, verbose_name='Settlement Type')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
                ('district', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='settlements', to='land_plots.district')),
            ],
            options={'db_table': 'settlements', 'unique_together': {('district', 'name')}},
        ),
        migrations.CreateModel(
            name='LandPlot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('cadastral_number', models.CharField(max_length=50, unique=True, validators=[django.core.validators.RegexValidator(message='Invalid cadastral number format. Expected format: XX:XX:XXXXXXX:XXXX', regex='^\\d{2}:\\d{2}:\\d{6,7}:\\d{1,6}$')], verbose_name='Cadastral Number')),
                ('address', models.TextField(verbose_name='Address')),
                ('area', models.DecimalField(decimal_places=2, max_digits=12, validators=[django.core.validators.MinValueValidator(0.01)], verbose_name='Area (sq.m.)')),
                ('geometry', django.contrib.gis.db.models.fields.PolygonField(srid=4326, verbose_name='Land Plot Geometry')),
                ('centroid', django.contrib.gis.db.models.fields.PointField(srid=4326, verbose_name='Land Plot Center')),
                ('ownership_type', models.CharField(choices=[('state', 'State'), ('municipal', 'Municipal'), ('private', 'Private'), ('shared', 'Shared')], default='private', max_length=20, verbose_name='Ownership Type')),
                ('is_verified', models.BooleanField(default=False, verbose_name='Is Verified')),
                ('verification_date', models.DateTimeField(blank=True, null=True, verbose_name='Verification Date')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
                ('notes', models.TextField(blank=True, null=True, verbose_name='Notes')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='land_plots.landcategory', verbose_name='Land Category')),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_land_plots', to=settings.AUTH_USER_MODEL, verbose_name='Created By')),
                ('district', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='land_plots.district', verbose_name='District')),
                ('purpose', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='land_plots.landpurpose', verbose_name='Land Purpose')),
                ('region', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='land_plots.region', verbose_name='Region')),
                ('settlement', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='land_plots.settlement', verbose_name='Settlement')),
            ],
            options={'db_table': 'land_plots', 'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='LandPlotOwner',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ownership_share', models.DecimalField(decimal_places=2, max_digits=5, validators=[django.core.validators.MinValueValidator(0.01), django.core.validators.MaxValueValidator(100.0)], verbose_name='Ownership Share (%)')),
                ('ownership_type', models.CharField(choices=[('full', 'Full Ownership'), ('joint', 'Joint Ownership'), ('shared', 'Shared Ownership')], default='full', max_length=20, verbose_name='Ownership Type')),
                ('is_primary_owner', models.BooleanField(default=False, verbose_name='Is Primary Owner')),
                ('ownership_document_number', models.CharField(blank=True, max_length=50, null=True, verbose_name='Ownership Document Number')),
                ('ownership_document_date', models.DateField(blank=True, null=True, verbose_name='Ownership Document Date')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('land_plot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='owners', to='land_plots.landplot')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='owned_land_plots', to=settings.AUTH_USER_MODEL)),
            ],
            options={'db_table': 'land_plot_owners', 'unique_together': {('land_plot', 'owner')}},
        ),
        migrations.CreateModel(
            name='LandPlotDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_type', models.CharField(choices=[('cadastral_passport', 'Cadastral Passport'), ('ownership_certificate', 'Ownership Certificate'), ('land_use_plan', 'Land Use Plan'), ('building_permit', 'Building Permit'), ('technical_passport', 'Technical Passport'), ('survey_plan', 'Survey Plan'), ('other', 'Other')], max_length=50, verbose_name='Document Type')),
                ('document_number', models.CharField(blank=True, max_length=50, null=True, verbose_name='Document Number')),
                ('document_date', models.DateField(blank=True, null=True, verbose_name='Document Date')),
                ('issued_by', models.CharField(blank=True, max_length=255, null=True, verbose_name='Issued By')),
                ('file', models.FileField(upload_to='land_plot_documents/', verbose_name='Document File')),
                ('file_name', models.CharField(max_length=255, verbose_name='File Name')),
                ('file_size', models.PositiveIntegerField(verbose_name='File Size (bytes)')),
                ('file_hash', models.CharField(max_length=64, verbose_name='File Hash')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Description')),
                ('is_verified', models.BooleanField(default=False, verbose_name='Is Verified')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True, verbose_name='Uploaded At')),
                ('land_plot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='documents', to='land_plots.landplot')),
                ('uploaded_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='uploaded_land_plot_documents', to=settings.AUTH_USER_MODEL, verbose_name='Uploaded By')),
            ],
            options={'db_table': 'land_plot_documents'},
        ),
        migrations.CreateModel(
            name='LandPlotEncumbrance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('encumbrance_type', models.CharField(choices=[('mortgage', 'Mortgage'), ('lease', 'Lease'), ('servitude', 'Servitude'), ('arrest', 'Arrest'), ('restriction', 'Restriction'), ('other', 'Other')], max_length=20, verbose_name='Encumbrance Type')),
                ('description', models.TextField(verbose_name='Description')),
                ('registration_number', models.CharField(blank=True, max_length=50, null=True, verbose_name='Registration Number')),
                ('registration_date', models.DateField(blank=True, null=True, verbose_name='Registration Date')),
                ('start_date', models.DateField(verbose_name='Start Date')),
                ('end_date', models.DateField(blank=True, null=True, verbose_name='End Date')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
                ('beneficiary', models.CharField(blank=True, max_length=255, null=True, verbose_name='Beneficiary')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_encumbrances', to=settings.AUTH_USER_MODEL, verbose_name='Created By')),
                ('land_plot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='encumbrances', to='land_plots.landplot')),
            ],
            options={'db_table': 'land_plot_encumbrances'},
        ),
        migrations.CreateModel(
            name='LandPlotValuation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('valuation_type', models.CharField(choices=[('market', 'Market Value'), ('cadastral', 'Cadastral Value'), ('investment', 'Investment Value'), ('mortgage', 'Mortgage Value')], max_length=20, verbose_name='Valuation Type')),
                ('value', models.DecimalField(decimal_places=2, max_digits=15, verbose_name='Value (RUB)')),
                ('valuation_date', models.DateField(verbose_name='Valuation Date')),
                ('valuator', models.CharField(blank=True, max_length=255, null=True, verbose_name='Valuator')),
                ('valuation_report_number', models.CharField(blank=True, max_length=50, null=True, verbose_name='Valuation Report Number')),
                ('notes', models.TextField(blank=True, null=True, verbose_name='Notes')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_valuations', to=settings.AUTH_USER_MODEL, verbose_name='Created By')),
                ('land_plot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='valuations', to='land_plots.landplot')),
            ],
            options={'db_table': 'land_plot_valuations', 'unique_together': {('land_plot', 'valuation_type', 'valuation_date')}},
        ),
    ]
