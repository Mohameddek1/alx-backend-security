from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block an IP address by adding it to the BlockedIP model'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='The IP address to block')
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address',
            default='Blocked via management command'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options['reason']
        
        # Check if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            self.stdout.write(
                self.style.WARNING(f'IP address {ip_address} is already blocked')
            )
            return
        
        # Add IP to blocked list
        blocked_ip = BlockedIP.objects.create(
            ip_address=ip_address,
            reason=reason
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully blocked IP address: {ip_address}')
        )
