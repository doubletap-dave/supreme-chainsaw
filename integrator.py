# integrator.py
from supreme_chainsaw import OvfManager

# Initialize logging
from loguru import logger
logger.add("ovf_operations.log", rotation="100 MB")

# Create an instance
ovf_manager = OvfManager(r"C:\Users\dave\OneDrive\Desktop\PowerFlex\pfmp-k8s-154L-20240503\pfmp-k8s-154L-20240503.ovf", debug=True)

# Make modifications
ovf_manager.add_network("TestNetwork", "Test network description")
ovf_manager.add_disk("disk2", 100, "file2")

# Add file reference
ovf_manager.add_file("file2", "disk2.vmdk")

# Save changes - manifest will be automatically updated
ovf_manager.save()

# Validate the OVF
is_valid, message = ovf_manager.validate()
if not is_valid:
    print(f"Validation failed: {message}")