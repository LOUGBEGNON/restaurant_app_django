from django.db import models
from django.db.models import BooleanField
from django.utils import timezone
from apps.authentication.models import User
from django.utils.translation import gettext_lazy as _



# Create your models here.
class Support(models.Model):
    author = models.ForeignKey(User, related_name="user_support", on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    subject= models.CharField(max_length=255)
    is_processed = BooleanField(default=False)
    creation_date = models.DateTimeField(
        _("creation date"),
        blank=True,
        db_index=True,
        default=timezone.now,
        help_text=_("Creation date, by default it is now."),
    )

    class Meta:
        verbose_name = "Support"
        verbose_name_plural = "Supports"


