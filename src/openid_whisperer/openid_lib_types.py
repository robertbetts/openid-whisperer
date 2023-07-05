from typing import TypedDict, Optional


class DevicecodeRequestInput(TypedDict):
    base_url: str
    tenant: str
    client_id: str
    scope: str
    resource: Optional[str]
    nonce: str
    response_type: Optional[str]
    code_challenge_method: Optional[str]
    prompt: Optional[str]


class DeviceCodeRequestResponse(TypedDict):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    message: Optional[str]
