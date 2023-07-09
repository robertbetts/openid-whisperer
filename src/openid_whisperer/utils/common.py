from typing import Dict


class GeneralPackageException(Exception):
    """Exception Recipe for API error responses"""

    def __init__(self, error_code: str, error_description: str):
        Exception.__init__(self, f"{error_code}: {error_description}")
        self.error_code: str = error_code
        self.error_description: str = error_description

    def to_dict(self) -> Dict[str, str]:
        return {
            "error_code": self.error_code,
            "error_description": self.error_description,
        }
