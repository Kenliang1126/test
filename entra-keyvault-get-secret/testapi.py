import os
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import sys
import logging

# Create a logger for the 'azure' SDK
logger = logging.getLogger('azure')
logger.setLevel(logging.DEBUG)

# Configure a console output
# handler = logging.StreamHandler(stream=sys.stdout)
# logger.addHandler(handler)

credential = ClientSecretCredential(
    tenant_id="280bf41d-bf29-4912-9f4a-42def550b467",
    client_id="fdcdc6b6-f65c-44c3-a584-1891b0d8920f",
    client_secret="",  # 别硬编码
    # client_secret=os.environ["AZURE_CLIENT_SECRET"],  # 别硬编码
)

secret_client = SecretClient(
    vault_url="https://keyvaultkenliang1126.vault.azure.net/",
    credential=credential,
    logging_enable=False,
)

secret = secret_client.get_secret("entra-oidc-client-secret")
print(secret.name)
print(secret.value)
