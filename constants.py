# constants.py

SUPPORTED_HASH_FUNCTIONS = ["sha1", "md5"]
SUPPORTED_OPERATIONS = ["INIT", "VERIFY"]
HASH_FUNCTION = "HASH_FUNCTION"
FILE_HASH = "FILE_HASH"
FILE_SIZE = "FILE_SIZE"
FILE_USER_OWNER = "FILE_USER_OWNER"
FILE_GROUP_OWNER = "FILE_GROUP_OWNER"
FILE_ACCESS_RIGHTS = "FILE_ACCESS_RIGHTS"
FILE_LAST_MODIFIED = "FILE_LAST_MODIFIED"
NEW_ATTR_PREFIX = 'NEW_'
OLD_ATTR_PREFIX = 'OLD_'
DELETED_ENTITY = 'DELETED_ENTITY'

current_file_information_storage = dict()
verification_document_data = dict()
chosen_hashing_algorithm = None
args = None
total_number_of_directories_parsed = 1
total_number_of_files_parsed = 0
warnings_given = 0
