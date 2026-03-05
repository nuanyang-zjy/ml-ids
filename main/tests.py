import uuid

from django.test import TestCase


# Create your tests here.
def generate_task_id():
    return str(uuid.uuid4())
