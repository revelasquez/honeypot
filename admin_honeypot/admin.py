from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from admin_honeypot.models import LoginAttempt, HashcashMetadata, Preferences, FakeUser


class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'get_ip_address', 'get_session_key', 'timestamp', 'get_path')
    list_filter = ('timestamp',)
    readonly_fields = ('path', 'username', 'ip_address', 'session_key', 'user_agent', 'hashcash_stamp')
    search_fields = ('username', 'ip_address', 'user_agent', 'path')

    def get_actions(self, request):
        actions = super(LoginAttemptAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def get_session_key(self, instance):
        return format_html('<a href="?session_key={sk}">{sk}</a>', sk=instance.session_key)

    get_session_key.short_description = _('Session')

    def get_ip_address(self, instance):
        return format_html('<a href="?ip_address={ip}">{ip}</a>', ip=instance.ip_address)

    get_ip_address.short_description = _('IP Address')

    def get_path(self, instance):
        return format_html('<a href="?path={path}">{path}</a>', path=instance.path)

    get_path.short_description = _('URL')

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class HashcashMetadataAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'is_used', 'salt', 'bits')
    list_filter = ('ip_address',)
    readonly_fields = ('ip_address', 'is_used', 'salt', 'bits')
    search_fields = ('ip_address',)


class PreferencesAdmin(admin.ModelAdmin):
    list_display = ('has_fail2ban_log', 'bits_to_increase', 'salt_length', 'hashcash_validity_in_minutes')
    list_display_links = ('has_fail2ban_log', 'bits_to_increase', 'salt_length', 'hashcash_validity_in_minutes')

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class FakeUserAdmin(admin.ModelAdmin):
    list_display = ('ID', 'username', 'password', 'salt')


admin.site.register(LoginAttempt, LoginAttemptAdmin)
admin.site.register(HashcashMetadata, HashcashMetadataAdmin)
admin.site.register(Preferences, PreferencesAdmin)
admin.site.register(FakeUser, FakeUserAdmin)