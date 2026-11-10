from azure.identity import DeviceCodeCredential
from azure.keyvault.secrets import SecretClient

credential = DeviceCodeCredential(
    tenant_id="280bf41d-bf29-4912-9f4a-42def550b467",
)

secret_client = SecretClient(
    vault_url="https://keyvaultkenliang1126.vault.azure.net/",
    credential=credential,
)

secret = secret_client.get_secret("entra-oidc-client-secret")
print(secret.name)
print(secret.value)
