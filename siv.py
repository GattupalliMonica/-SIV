#!/usr/bin/python3
import os
import argparse
import sys
import hashlib
import argparse
import sys
import grp
import pwd
import time
import json
from pathlib import Path
from datetime import datetime

from constants import (
    SUPPORTED_HASH_FUNCTIONS, SUPPORTED_OPERATIONS, HASH_FUNCTION, FILE_HASH, FILE_SIZE, FILE_USER_OWNER, FILE_GROUP_OWNER, 
    FILE_ACCESS_RIGHTS, FILE_LAST_MODIFIED, NEW_ATTR_PREFIX, OLD_ATTR_PREFIX, DELETED_ENTITY,
    current_file_information_storage, verification_document_data, chosen_hashing_algorithm, args, total_number_of_directories_parsed,
    total_number_of_files_parsed, warnings_given,
)

class FileVerifier:
    def __init__(self, target_dir):
        self.target_dir = target_dir
    
    def does_directory_exist(dir_name):
        # Using os.path.exists to check directory existence
        return os.path.exists(dir_name)

    def check_file_directory(self, file_path):
        file_base_name = os.path.basename(file_path)
        
        if self.target_dir in file_base_name:
            print(f"ERROR: The file '{os.path.basename(file_path)}' is within the target directory '{self.target_dir}' -> '{file_base_name}'")
            return False
        
        return True

    @staticmethod
    def verify_files_location(target_dir, verification_file_path, report_file_path):
        verifier = FileVerifier(target_dir)

        if not verifier.check_file_directory(verification_file_path):
            return False  # Verification file is inside the target directory

        if not verifier.check_file_directory(report_file_path):
            return False  # Report file is inside the target directory

        return True


class FileUtilities:
    LIST_OF_SUPPORTED_HASH_FUNCTIONS = ["sha1", "md5"]

    def __init__(self):
        pass  # Constructor, you can add initialization logic here if needed

    def is_requested_hash_function_okay(self, requested_hash_technique):
        return requested_hash_technique in self.LIST_OF_SUPPORTED_HASH_FUNCTIONS

    def overwrite_file(self, file_to_overwrite):
        try:
            with open(file_to_overwrite, "w"):
                pass  # This will create or truncate the file if it exists
            
        except Exception as exception_message:
            print(f"Error: {exception_message}")
            


def process_directory_data(absolute_file_path_to_process, selected_hashing_function):
    file_statistics_information = os.stat(absolute_file_path_to_process)
    user_identifier = file_statistics_information.st_uid
    group_identifier = file_statistics_information.st_gid
    username_of_owner = pwd.getpwuid(user_identifier)[0]   # extracting the username of the file owner
    groupname_of_owner = grp.getgrgid(group_identifier)[0]  # extracting the groupname of the file owner

    def calculate_file_hash(path_to_file_or_directory, chosen_hashing_algorithm):
        hash_object = hashlib.sha1() if chosen_hashing_algorithm == SUPPORTED_HASH_FUNCTIONS[0] else hashlib.md5() if chosen_hashing_algorithm == SUPPORTED_HASH_FUNCTIONS[1] else None
        if os.path.isdir(path_to_file_or_directory):
            hash_object.update((path_to_file_or_directory * 1024).encode("utf-8")) if hash_object else None
        else:
            with open(path_to_file_or_directory, 'rb') as file_to_hash:
                while True:
                    block = file_to_hash.read(2**10)
                    if not block:
                        break
                    hash_object.update(block) if hash_object else None
        return hash_object.hexdigest() if hash_object else ""

    file_information_details = {
        FILE_SIZE: str(file_statistics_information.st_size),
        FILE_USER_OWNER: username_of_owner,
        FILE_GROUP_OWNER: groupname_of_owner,
        FILE_ACCESS_RIGHTS: str(file_statistics_information.st_mode),
        FILE_LAST_MODIFIED: str(file_statistics_information.st_mtime),
        FILE_HASH: calculate_file_hash(absolute_file_path_to_process, selected_hashing_function)
    }

    current_file_information_storage[absolute_file_path_to_process] = file_information_details


def traverse_directory_and_get(directory_name_to_search, requested_operation_mode):
    global total_number_of_files_parsed, total_number_of_directories_parsed

    # Dictionary to store counts of files and directories
    counts = {'files': 0, 'directories': 0}

    # Determine if the requested operation mode is supported
    supported_operation_mode = requested_operation_mode if requested_operation_mode in SUPPORTED_OPERATIONS else None

    process_directory_data(directory_name_to_search, chosen_hashing_algorithm) if supported_operation_mode else print("Error: Invalid Operation Mode")

    # Fetch sorted file entries in the directory using pathlib.Path
    directory_path = Path(directory_name_to_search)
    entries_to_process = sorted(directory_path.iterdir(), key=lambda x: x.name)

    for current_entry in entries_to_process:
        current_path_to_process = str(current_entry)  # Convert Path object to string

        if current_entry.is_dir():
            traverse_directory_and_get(current_path_to_process, requested_operation_mode=supported_operation_mode)
            counts['directories'] += 1
        elif current_entry.is_file():
            counts['files'] += 1 if supported_operation_mode else 0
            process_directory_data(current_path_to_process, chosen_hashing_algorithm) if supported_operation_mode else print(f"Error: Invalid Operation Mode - {supported_operation_mode}")
        else:
            assert False, f"Skipping {current_path_to_process}: Entry is not a file or directory"

    # Update the global counts after traversal
    total_number_of_files_parsed += counts['files']
    total_number_of_directories_parsed += counts['directories']

class ReportGenerator:
    def __init__(self, absolute_path_of_monitored_directory, absolute_path_of_verification_file, absolute_path_of_report_file):
        self.absolute_path_of_monitored_directory = absolute_path_of_monitored_directory
        self.absolute_path_of_verification_file = absolute_path_of_verification_file
        self.absolute_path_of_report_file = absolute_path_of_report_file

    def generate_initialization_report(self, total_number_of_directories_parsed, total_number_of_files_parsed, time_taken_for_initialization):
        report_content = (
            f"Observed Location Path                 : {os.path.abspath(self.absolute_path_of_monitored_directory)}\n"
            f"Verification File Path                 : {os.path.abspath(self.absolute_path_of_verification_file)}\n"
            f"Count of Examined Directories          : {total_number_of_directories_parsed}\n"
            f"Count of Examined Files                : {total_number_of_files_parsed}\n"
            f"Initiation Duration                    : {time_taken_for_initialization} seconds\n"
        )
        self._write_report_content(report_content)

    def generate_verification_report(self, total_number_of_directories_parsed, total_number_of_files_parsed, total_number_of_warnings_issued, time_taken_for_verification):
        report_content = (
            f"Observed Location Path               : {os.path.abspath(self.absolute_path_of_monitored_directory)}\n"
            f"Verification File Path               : {os.path.abspath(self.absolute_path_of_verification_file)}\n"
            f"Outcome File Path                    : {os.path.abspath(self.absolute_path_of_report_file)}\n"
            f"Count of Examined Directories        : {total_number_of_directories_parsed}\n"
            f"Count of Examined Files              : {total_number_of_files_parsed}\n"
            f"Count of Warnings Issued             : {total_number_of_warnings_issued}\n"
            f"Verification Duration                : {time_taken_for_verification} seconds\n"
        )
        self._write_report_content(report_content)

    def _write_report_content(self, content_to_write):
        with open(os.path.abspath(self.absolute_path_of_report_file), "a") as file_pointer:
            file_pointer.write(content_to_write)
        print(content_to_write)
            

def generate_verification_report():
    global warnings_given
    verification_details = {}

    for inspected_path_or_document, current_data in current_file_information_storage.items():
        verification_data = verification_document_data.get(inspected_path_or_document)

        if verification_data:
            modified_content = {}

            attributes_to_inspect = [
                'FILE_SIZE', 'FILE_USER_OWNER', 'FILE_GROUP_OWNER',
                'FILE_ACCESS_RIGHTS', 'FILE_LAST_MODIFIED', 'FILE_HASH'
            ]

            for attribute in attributes_to_inspect:
                current_value = current_data.get(attribute)
                verification_value = verification_data.get(attribute)

                if verification_value != current_value:
                    modified_content.update({
                        f"{NEW_ATTR_PREFIX}{attribute}": current_value,
                        f"{OLD_ATTR_PREFIX}{attribute}": verification_value
                    })
                    warnings_given += 1

            if modified_content:
                verification_details[inspected_path_or_document] = modified_content
        else:
            verification_details[inspected_path_or_document] = current_data

    for missing_entity in verification_document_data.keys():
        if missing_entity not in current_file_information_storage and missing_entity != 'HASH_FUNCTION':
            deleted_entity_data = {
                DELETED_ENTITY: missing_entity
            }
            warnings_given += 1
            verification_details[missing_entity] = deleted_entity_data

    if verification_details:
        for details in verification_details.items():
            if 'FILE_LAST_MODIFIED' in details:
                details['FILE_LAST_MODIFIED'] = str(datetime.fromtimestamp(float(details['FILE_LAST_MODIFIED'])))

        print(json.dumps(verification_details, indent=4))

        with open(os.path.abspath(args.report_file), "w") as file_pointer:
            json.dump(verification_details, file_pointer, indent=4)
            file_pointer.write("\n")


def report_verification_mode(verification_path):
    global verification_document_data, chosen_hashing_algorithm

    # Confirm the existence of the file using the 'path.exists' method directly
    assert os.path.exists(verification_path), f"The specified verification file '{verification_path}' does not exist."

    with open(verification_path, "r") as file_handle:
        # Load JSON data from the file
        verification_document_data = json.load(file_handle)
    
    # Lambda function using 'get' to retrieve the hash function from the loaded data
    retrieve_hash_function = lambda information: information.get(HASH_FUNCTION)
    
    # Retrieve the hash function and ensure its presence in the loaded data
    chosen_hashing_algorithm = retrieve_hash_function(verification_document_data)
    assert chosen_hashing_algorithm is not None, "The verification file is invalid; hash function is missing."
    
    return True


if __name__=='__main__':
    # Create a guide with some examples showing the syntax.
    # Setting up the ArgumentParser
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='System Integrity Verifier (SIV).',
        epilog=f'For Example:\n'
                f'    {sys.argv[0]} -i -D /monitored_directory/ -V verification_db.csv -R my_report.txt -H md5\n'
                f'    {sys.argv[0]} -v -D /monitored_directory/ -V verification_db.csv -R my_report.txt'
    )

    # Parsing arguments
    # Add parser.add_argument() for your specific arguments

    # You can test the output of the help by using:
    # parser.parse_args(['--help'])

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-i',
        action='store_true',
        dest='Initialization_mode',
        help='Enable the INITIALIZATION Mode'
    )
    group.add_argument(
        '-v',
        action='store_true',
        dest='verification_mode',
        help='Enable the VERIFICATION mode'
    )

    # Define arguments separately
    arguments = [
        ('-D', 'monitored_directory', str, 'Directory to be Monitored'),
        ('-V', 'verification_file', str, 'Verification DataBase (DB) file in .CSV format'),
        ('-R', 'report_file', str, 'Report file name'),
        ('-H', 'hash_function', str, 'Hashing Algorithm (used only for Initialization Mode)', SUPPORTED_HASH_FUNCTIONS)
    ]

    for arg_data in arguments:
        arg_short, dest, arg_type, arg_help = arg_data[:4]
        kwargs = {
            'type': arg_type,
            'help': arg_help,
            'dest': dest,
        }
        if len(arg_data) == 5:
            kwargs['choices'] = arg_data[4]
        if arg_short in ('-D', '-V', '-R'):
            kwargs['required'] = True
        parser.add_argument(arg_short, **kwargs)

    # Parse the arguments
    args = parser.parse_args()

    SUPPORTED_OPERATIONS = ["Initialization Mode", "Verification Mode"]
    report_generator = ReportGenerator(args.monitored_directory, args.verification_file, args.report_file)
    file_utils = FileUtilities()

    # Lambda functions for assertions
    target_dir_exists = lambda dir_path: FileVerifier.does_directory_exist(dir_path)
    verify_files_location = lambda dir_path, verification_file, report_file: FileVerifier.verify_files_location(dir_path, verification_file, report_file)
    hash_function_supported = lambda hash_func: file_utils.is_requested_hash_function_okay(hash_func)
    verify_parse_verification = lambda verification_file: report_verification_mode(os.path.abspath(verification_file))

    if args.Initialization_mode:
        chosen_hashing_algorithm = args.hash_function
        
        assert target_dir_exists(args.monitored_directory), "ERROR: The targeted directory does not exist."
        assert verify_files_location(args.monitored_directory, args.verification_file, args.report_file), "ERROR: The verification or report file is inside the targeted directory."
        assert hash_function_supported(args.hash_function), f"ERROR: The hash function '{args.hash_function}' is not supported."
        
        file_utils.overwrite_file(args.verification_file)
        file_utils.overwrite_file(args.report_file)
        
        abs_path = os.path.abspath(args.monitored_directory)
        starting_time = time.time()
        traverse_directory_and_get(abs_path, SUPPORTED_OPERATIONS[0])
        time_to_complete_operation = time.time() - starting_time
        
        current_file_information_storage[HASH_FUNCTION] = chosen_hashing_algorithm
        
        with open(os.path.abspath(args.verification_file), "w") as file:
            json.dump(current_file_information_storage, file, indent=4)
        
        for file_dir in current_file_information_storage.keys():
            try:
                if FILE_LAST_MODIFIED in current_file_information_storage[file_dir].keys():
                    current_file_information_storage[file_dir][FILE_LAST_MODIFIED] = str(datetime.fromtimestamp(
                        float(current_file_information_storage[file_dir][FILE_LAST_MODIFIED])))
            except AttributeError:
                pass
        
        print(json.dumps(current_file_information_storage, indent=4))
        
        # Example usage:
        report_generator.generate_initialization_report(total_number_of_directories_parsed,
                                                    total_number_of_files_parsed,
                                                    time_to_complete_operation)
    else:  # For Verification Mode
        assert verify_parse_verification(args.verification_file), "ERROR: The verification file doesn't exist or couldn't be parsed."
        assert verify_files_location(args.monitored_directory, args.verification_file, args.report_file), "ERROR: The verification or report file is inside the targeted directory."
        
        file_utils.overwrite_file(args.report_file)
        abs_path = os.path.abspath(args.monitored_directory)
        starting_time = time.time()
        traverse_directory_and_get(abs_path, SUPPORTED_OPERATIONS[1])
        time_to_complete_operation = time.time() - starting_time
        
        generate_verification_report()
        
        report_generator.generate_verification_report(total_number_of_directories_parsed,
                                                    total_number_of_files_parsed,
                                                    warnings_given,
                                                    time_to_complete_operation)
