import re
from datetime import datetime
from django.core.management.base import BaseCommand
from logs.models import LogEntry

log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/.*?" (\d+) (\d+)'
)

class Command(BaseCommand):
    help = "Import limited number of logs from dataset"

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str)
        parser.add_argument('--limit', type=int, default=500000)

    def handle(self, *args, **options):
        file_path = options['file_path']
        limit = options['limit']

        log_objects = []
        count = 0

        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if count >= limit:
                    break

                match = log_pattern.match(line)
                if match:
                    ip = match.group(1)
                    time_str = match.group(2)
                    method = match.group(3)
                    url = match.group(4)
                    status = int(match.group(5))
                    size = int(match.group(6))

                    timestamp = datetime.strptime(
                        time_str, "%d/%b/%Y:%H:%M:%S %z"
                    )

                    log_objects.append(
                        LogEntry(
                            ip_address=ip,
                            timestamp=timestamp,
                            method=method,
                            url=url,
                            status_code=status,
                            response_size=size
                        )
                    )

                    count += 1

                    # Insert every 5000 logs
                    if len(log_objects) >= 5000:
                        LogEntry.objects.bulk_create(log_objects)
                        log_objects = []
                        self.stdout.write(f"Inserted {count} logs...")

        # Insert remaining logs
        if log_objects:
            LogEntry.objects.bulk_create(log_objects)

        self.stdout.write(
            self.style.SUCCESS(f"Successfully imported {count} logs!")
        )
