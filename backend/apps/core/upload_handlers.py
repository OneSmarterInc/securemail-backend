"""Bounded memory-only multipart uploads; never fall back to plaintext temp files."""

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.core.files.uploadhandler import MemoryFileUploadHandler


class BoundedMemoryUploadHandler(MemoryFileUploadHandler):
    def handle_raw_input(self, input_data, META, content_length, boundary, encoding=None):
        if content_length is not None and content_length > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            raise RequestDataTooBig("Upload request exceeds the allowed size.")
        self.activated = True
        self.total_bytes = 0

    def receive_data_chunk(self, raw_data: bytes, start: int):
        # Aggregate all files in the request, including multipart requests with
        # an absent or understated length. Check before writing to BytesIO.
        self.total_bytes += len(raw_data)
        if self.total_bytes > settings.MAX_UPLOAD_BYTES:
            self.file.close()
            raise RequestDataTooBig("Combined upload size exceeds the allowed limit.")
        return super().receive_data_chunk(raw_data, start)
