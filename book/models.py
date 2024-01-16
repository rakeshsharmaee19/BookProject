import uuid

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


def value_validator(value):
    if 5 < value < 0 and value is None:
        raise ValidationError(
            _('%(value)s is not in between 0 and 5'),
            params={'value': value},
        )


class ModelMeta(models.Model):
    created_by = models.CharField(max_length=150, null=True, blank=True)
    updated_by = models.CharField(max_length=150, null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True, auto_now=False)
    updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UserFollows(ModelMeta):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='following')
    followed_user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='followed_by')

    class Meta:
        unique_together = ('user', 'followed_user')
        ordering = ('-created_date',)
        db_table = 'user_following'
        verbose_name = 'user_following'
        verbose_name_plural = 'user_followings'

    def __str__(self):
        return f'{self.user} follows {self.followed_user}'


class Ticket(ModelMeta):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=128)
    description = models.TextField(max_length=2048, blank=True)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    image = models.ImageField(null=True, blank=True, upload_to='images/', default=None)

    class Meta:
        ordering = ('-created_date',)
        db_table = 'ticket'
        verbose_name = 'ticket'
        verbose_name_plural = 'tickets'

    def __str__(self):
        return f'{self.user} {self.title}'


class Review(ModelMeta):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)
    rating = models.SmallIntegerField(validators=[value_validator])
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    headline = models.CharField(max_length=128)
    body = models.TextField(max_length=8192)

    class Meta:
        ordering = ('-created_date',)
        db_table = 'review'
        verbose_name = 'review'
        verbose_name_plural = 'reviews'

    def __str__(self):
        return f'{self.user} {self.ticket} {self.rating}'

