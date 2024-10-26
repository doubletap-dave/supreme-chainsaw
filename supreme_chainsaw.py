# supreme_chainsaw.py

import xml.etree.ElementTree as ET
from xml.dom import minidom
import subprocess
import os
import platform
import shutil
import hashlib
import glob
from typing import Dict, List, Optional, Tuple
from loguru import logger
import tempfile
import time


class OvfValidator:
    """Handles validation of OVF files with enhanced logging capabilities."""

    def __init__(self, ovftool_path: str, debug: bool = False):
        """
        Initialize the validator.

        Args:
            ovftool_path: Path to ovftool executable
            debug: Enable debug mode with verbose logging
        """
        self.ovftool_path = ovftool_path
        self.debug = debug

    def _get_debug_args(self, temp_log_file: str) -> List[str]:
        """Get debug command line arguments if debug mode is enabled."""
        args = ['--noSSLVerify']  # Always include noSSLVerify
        if self.debug:
            args.extend([
                '--X:logLevel=verbose',
                f'--X:logFile={temp_log_file}'
            ])
        return args

    @staticmethod
    def _process_validation_output(result: subprocess.CompletedProcess,
                                   log_file: Optional[str] = None) -> Tuple[bool, str]:
        """Process validation output and logs."""
        # Check if validation succeeded
        success = result.returncode == 0

        # Build detailed message
        messages = []

        if result.stdout:
            messages.append("Output:")
            messages.append(result.stdout)

        if result.stderr:
            messages.append("Errors:")
            messages.append(result.stderr)

        # Add debug log contents if available
        if log_file and os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    messages.append("Debug Log:")
                    messages.append(f.read())
            except Exception as e:
                messages.append(f"Warning: Could not read debug log: {str(e)}")

        return success, "\n".join(messages)

    def validate_schema(self, ovf_path: str) -> Tuple[bool, str]:
        """
        Validate OVF schema using ovftool with optional debug logging.

        Args:
            ovf_path: Path to OVF file to validate

        Returns:
            Tuple containing:
            - bool: True if validation succeeded
            - str: Validation output message
        """
        temp_log_file = None
        try:
            # Create temporary file for debug log if needed
            if self.debug:
                temp_log_file = os.path.join(
                    tempfile.gettempdir(),
                    f"ovftool_schema_validation_{os.path.basename(ovf_path)}_{int(time.time())}.log"
                )

            # Build command
            cmd = [self.ovftool_path, '--schemaValidate']  # Removed --noSSLVerify here since it's in _get_debug_args
            cmd.extend(self._get_debug_args(temp_log_file))
            cmd.append(ovf_path)

            # Run validation
            logger.debug(f"Running schema validation command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            return self._process_validation_output(result, temp_log_file)

        except Exception as e:
            return False, f"Validation failed with error: {str(e)}"

        finally:
            # Cleanup temp log file
            if temp_log_file and os.path.exists(temp_log_file):
                try:
                    os.remove(temp_log_file)
                except Exception as e:
                    logger.warning(f"Failed to remove temporary log file {temp_log_file}: {str(e)}")

    def validate_signature(self, ovf_path: str) -> Tuple[bool, str]:
        """
        Validate OVF signature using ovftool with optional debug logging.

        Args:
            ovf_path: Path to OVF file to validate

        Returns:
            Tuple containing:
            - bool: True if validation succeeded
            - str: Validation output message
        """
        temp_log_file = None
        try:
            # Create temporary file for debug log if needed
            if self.debug:
                temp_log_file = os.path.join(
                    tempfile.gettempdir(),
                    f"ovftool_signature_validation_{os.path.basename(ovf_path)}_{int(time.time())}.log"
                )

            # Build command
            cmd = [self.ovftool_path]
            cmd.extend(self._get_debug_args(temp_log_file))
            cmd.append(ovf_path)

            # Run validation
            logger.debug(f"Running signature validation command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            return self._process_validation_output(result, temp_log_file)

        except Exception as e:
            return False, f"Validation failed with error: {str(e)}"

        finally:
            # Cleanup temp log file
            if temp_log_file and os.path.exists(temp_log_file):
                try:
                    os.remove(temp_log_file)
                except Exception as e:
                    logger.warning(f"Failed to remove temporary log file {temp_log_file}: {str(e)}")

class ManifestManager:
    """Handles manifest file operations."""

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def create_manifest(self, directory: str, output_path: str) -> None:
        """Create a manifest file with SHA256 hashes for all files in directory."""
        try:
            with open(output_path, 'w') as mf:
                for filepath in glob.glob(os.path.join(directory, '*')):
                    if filepath.endswith('.mf') or filepath.endswith('.cert'):
                        continue
                    filename = os.path.basename(filepath)
                    sha256 = self.calculate_sha256(filepath)
                    mf.write(f'SHA256({filename})= {sha256}\n')
            logger.success(f"Created manifest file at {output_path}")
        except Exception as e:
            logger.error(f"Failed to create manifest: {str(e)}")
            raise


class OvfManager:
    """
    A class to manage OVF (Open Virtualization Format) files.
    Provides functionality to modify, validate and manipulate OVF descriptors.
    """

    NAMESPACES = {
        'ovf': 'http://schemas.dmtf.org/ovf/envelope/1',
        'vmw': 'http://www.vmware.com/schema/ovf',
        'rasd': 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData',
        'vssd': 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'cim': 'http://schemas.dmtf.org/wbem/wscim/1/common'
    }

    def __init__(self, ovf_path: str, debug: bool = False):
        """
        Initialize the OVF manager with a path to an OVF file.

        Args:
            ovf_path: Path to the OVF file
            debug: Enable debug mode with verbose logging
        """
        logger.info(f"Initializing OVF Manager with file: {ovf_path}")

        self.ovf_path = ovf_path
        self.ovf_dir = os.path.dirname(ovf_path)
        self.backup_path = None
        self.manifest_path = os.path.join(self.ovf_dir, os.path.splitext(os.path.basename(ovf_path))[0] + ".mf")

        self.ovftool_path = self._get_ovftool_path()
        self.validator = OvfValidator(self.ovftool_path, debug=debug)  # Pass debug flag
        self.manifest_manager = ManifestManager()

        # Register all namespaces
        for prefix, uri in self.NAMESPACES.items():
            ET.register_namespace(prefix, uri)

        try:
            self.tree = ET.parse(ovf_path)
            self.root = self.tree.getroot()
            logger.success("Successfully parsed OVF file")
        except Exception as e:
            logger.error(f"Failed to parse OVF file: {str(e)}")
            raise

    def _get_ovftool_path(self) -> str:
        """Get the path to ovftool based on the current operating system."""
        base_dir = "ovftool"
        system = platform.system().lower()

        if system == "windows":
            return os.path.join(base_dir, "windows", "ovftool.exe")
        elif system == "linux":
            return os.path.join(base_dir, "linux", "ovftool")
        elif system == "darwin":
            return os.path.join(base_dir, "mac", "ovftool")
        else:
            raise OSError(f"Unsupported operating system: {system}")

    def _backup_files(self) -> None:
        """Create backups of the OVF and manifest files."""
        try:
            # Backup OVF file
            self.backup_path = f"{self.ovf_path}.backup"
            shutil.copy2(self.ovf_path, self.backup_path)

            # Backup manifest file if it exists
            if os.path.exists(self.manifest_path):
                shutil.copy2(self.manifest_path, f"{self.manifest_path}.backup")

            logger.info("Created backup files")
        except Exception as e:
            logger.error(f"Failed to create backups: {str(e)}")
            raise

    def _restore_backups(self) -> None:
        """Restore files from backups if available."""
        try:
            if self.backup_path and os.path.exists(self.backup_path):
                shutil.copy2(self.backup_path, self.ovf_path)
                os.remove(self.backup_path)

                # Restore manifest backup if it exists
                manifest_backup = f"{self.manifest_path}.backup"
                if os.path.exists(manifest_backup):
                    shutil.copy2(manifest_backup, self.manifest_path)
                    os.remove(manifest_backup)

                logger.info("Restored files from backup")
        except Exception as e:
            logger.error(f"Failed to restore backups: {str(e)}")
            raise

    def update_manifest(self) -> None:
        """Update the manifest file with new SHA256 hashes."""
        try:
            self.manifest_manager.create_manifest(self.ovf_dir, self.manifest_path)
        except Exception as e:
            logger.error(f"Failed to update manifest: {str(e)}")
            raise

    def validate(self) -> Tuple[bool, str]:
        """Validate the OVF file using schema and signature validation."""
        schema_valid, schema_msg = self.validator.validate_schema(self.ovf_path)
        if not schema_valid:
            return False, f"Schema validation failed: {schema_msg}"

        sign_valid, sign_msg = self.validator.validate_signature(self.ovf_path)
        if not sign_valid:
            return False, f"Signature validation failed: {sign_msg}"

        return True, "Validation successful"

    def get_networks(self) -> List[Dict[str, str]]:
        """
        Get all networks defined in the OVF.

        Returns:
            List[Dict[str, str]]: List of network information
        """
        networks = []
        try:
            network_section = self.root.find('.//{' + self.NAMESPACES['ovf'] + '}NetworkSection')
            if network_section is not None:
                for network in network_section.findall('.//{' + self.NAMESPACES['ovf'] + '}Network'):
                    name = network.get('{' + self.NAMESPACES['ovf'] + '}name')
                    desc = network.find('Description').text if network.find('Description') is not None else ""
                    networks.append({'name': name, 'description': desc})
            return networks
        except Exception as e:
            logger.error(f"Failed to get networks: {str(e)}")
            return []

    def get_disks(self) -> List[Dict[str, str]]:
        """
        Get all disks defined in the OVF.

        Returns:
            List[Dict[str, str]]: List of disk information
        """
        disks = []
        try:
            disk_section = self.root.find('.//{' + self.NAMESPACES['ovf'] + '}DiskSection')
            if disk_section is not None:
                for disk in disk_section.findall('.//{' + self.NAMESPACES['ovf'] + '}Disk'):
                    disk_info = {
                        'id': disk.get('{' + self.NAMESPACES['ovf'] + '}diskId'),
                        'capacity': disk.get('{' + self.NAMESPACES['ovf'] + '}capacity'),
                        'file_ref': disk.get('{' + self.NAMESPACES['ovf'] + '}fileRef')
                    }
                    disks.append(disk_info)
            return disks
        except Exception as e:
            logger.error(f"Failed to get disks: {str(e)}")
            return []

    def add_network(self, name: str, description: str) -> bool:
        """
        Add a new network to the OVF descriptor.

        Args:
            name: Name of the network
            description: Network description

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Find NetworkSection
            network_section = self.root.find('.//{' + self.NAMESPACES['ovf'] + '}NetworkSection')
            if network_section is None:
                logger.error("NetworkSection not found in OVF")
                return False

            # Check if network already exists
            existing_networks = self.get_networks()
            if any(net['name'] == name for net in existing_networks):
                logger.error(f"Network {name} already exists")
                return False

            # Create new Network element
            network = ET.SubElement(network_section, '{' + self.NAMESPACES['ovf'] + '}Network')
            network.set('{' + self.NAMESPACES['ovf'] + '}name', name)

            # Add Description
            desc_elem = ET.SubElement(network, 'Description')
            desc_elem.text = description

            logger.success(f"Added network: {name}")
            return True

        except Exception as e:
            logger.error(f"Failed to add network: {str(e)}")
            return False

    def add_disk(self, disk_id: str, capacity_gb: int, file_ref: str) -> bool:
        """
        Add a new disk to the OVF descriptor.

        Args:
            disk_id: Unique identifier for the disk
            capacity_gb: Disk capacity in gigabytes
            file_ref: Reference to the file containing the disk

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Find DiskSection
            disk_section = self.root.find('.//{' + self.NAMESPACES['ovf'] + '}DiskSection')
            if disk_section is None:
                logger.error("DiskSection not found in OVF")
                return False

            # Check if disk ID already exists
            existing_disks = self.get_disks()
            if any(disk['id'] == disk_id for disk in existing_disks):
                logger.error(f"Disk with ID {disk_id} already exists")
                return False

            # Create new Disk element
            disk = ET.SubElement(disk_section, '{' + self.NAMESPACES['ovf'] + '}Disk')

            # Set disk attributes
            capacity_bytes = capacity_gb * 1024 * 1024 * 1024
            disk.set('{' + self.NAMESPACES['ovf'] + '}diskId', disk_id)
            disk.set('{' + self.NAMESPACES['ovf'] + '}capacity', str(capacity_bytes))
            disk.set('{' + self.NAMESPACES['ovf'] + '}capacityAllocationUnits', 'byte')
            disk.set('{' + self.NAMESPACES['ovf'] + '}fileRef', file_ref)
            disk.set('{' + self.NAMESPACES['ovf'] + '}format',
                     'http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized')

            logger.success(f"Added disk: {disk_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add disk: {str(e)}")
            return False

    def add_file(self, file_id: str, href: str) -> bool:
        """
        Add a new file reference to the OVF descriptor.

        Args:
            file_id: Unique identifier for the file
            href: Path to the file relative to the OVF file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Find References section
            references = self.root.find('.//{' + self.NAMESPACES['ovf'] + '}References')
            if references is None:
                logger.error("References section not found in OVF")
                return False

            # Check if file ID already exists
            existing_files = references.findall('.//{' + self.NAMESPACES['ovf'] + '}File')
            if any(f.get('{' + self.NAMESPACES['ovf'] + '}id') == file_id for f in existing_files):
                logger.error(f"File with ID {file_id} already exists")
                return False

            # Create new File element
            file_elem = ET.SubElement(references, '{' + self.NAMESPACES['ovf'] + '}File')
            file_elem.set('{' + self.NAMESPACES['ovf'] + '}id', file_id)
            file_elem.set('{' + self.NAMESPACES['ovf'] + '}href', href)

            logger.success(f"Added file reference: {file_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add file reference: {str(e)}")
            return False

    def save(self, output_path: Optional[str] = None) -> bool:
        """Save the modified OVF file and update manifest."""
        try:
            save_path = output_path or self.ovf_path

            # Create backups if overwriting original
            if not output_path:
                self._backup_files()

            # Convert to string with proper formatting
            xmlstr = minidom.parseString(ET.tostring(self.root)).toprettyxml(indent='  ')
            xmlstr = '\n'.join([line for line in xmlstr.split('\n') if line.strip()])

            # Write to file
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(xmlstr)

            # Update manifest
            self.update_manifest()

            logger.success(f"Saved OVF to: {save_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save OVF: {str(e)}")
            if self.backup_path:
                self._restore_backups()
            return False