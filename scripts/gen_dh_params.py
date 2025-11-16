"""
Diffie-Hellman Parameters Generation Script.
Generates and saves DH parameters for secure key exchange.
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


class DiffieHellmanParametersGenerator:
    """Handles generation and management of Diffie-Hellman parameters."""
    
    CERTIFICATES_DIRECTORY = "certs"
    DH_PARAMETERS_FILENAME = "dh_parameters.pem"
    DEFAULT_KEY_SIZE = 1024  # bits
    
    def __init__(self):
        """Initialize DH parameters generator."""
        self.parameters_path = os.path.join(self.CERTIFICATES_DIRECTORY, self.DH_PARAMETERS_FILENAME)

    def _ensure_certificates_directory(self):
        """Create certificates directory if it doesn't exist."""
        os.makedirs(self.CERTIFICATES_DIRECTORY, exist_ok=True)

    def generate_dh_parameters(self, key_size: int = DEFAULT_KEY_SIZE):
        """
        Generate and save DH parameters.
        
        Args:
            key_size: Bit size for DH parameters (default: 1024)
        """
        print(f"\n=== Diffie-Hellman Parameters Generation ({key_size}-bit) ===")
        
        self._ensure_certificates_directory()
        
        # Check if parameters already exist
        if os.path.exists(self.parameters_path):
            print(f"[*] DH parameters already exist at: {self.parameters_path}")
            print("[*] Skipping generation to avoid overwriting.")
            return

        print(f"[*] Generating {key_size}-bit DH parameters (this may take a moment)...")
        
        # Generate DH parameters
        dh_parameters = dh.generate_parameters(
            generator=2,  # Standard generator
            key_size=key_size, 
            backend=default_backend()
        )

        # Serialize to PEM format
        serialized_parameters = dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        
        # Save to file
        self._save_parameters_to_file(serialized_parameters)
        
        print(f"[SUCCESS] DH parameters saved to: {self.parameters_path}")
        print("[IMPORTANT] Run this script BEFORE starting client/server applications.")

    def _save_parameters_to_file(self, parameters_data: bytes):
        """
        Save DH parameters to file.
        
        Args:
            parameters_data: Serialized DH parameters
        """
        with open(self.parameters_path, "wb") as parameters_file:
            parameters_file.write(parameters_data)


def main():
    """Main execution function for DH parameters generation."""
    dh_generator = DiffieHellmanParametersGenerator()
    dh_generator.generate_dh_parameters()


if __name__ == '__main__':
    main()