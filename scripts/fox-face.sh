#/bin/bash
#
# Regards, the Alveare Solutions society.
#
declare -A DEFAULT
declare -A CHECKSUM_ALGORITHMS
declare -A ENCRYPTION_BEHAVIOURS
declare -A DECRYPTION_BEHAVIOURS

CONF_FILE_PATH="$1"

if [ ! -z "$CONF_FILE_PATH" ]; then
    source $CONF_FILE_PATH
fi

# FETCHERS

function fetch_mapped_block_devices_with_encryption () {
    MAPPED_BLOCK_DEVICES=( `ls -1 ${DEFAULT['mapper-dir']}` )
    if [ ${#MAPPED_BLOCK_DEVICES[@]} -eq 0 ]; then
        warning_msg "No mapped block devices found."
        return 1
    fi
    ENCRYPTED_PARTITION_LABELS=(
        `lsblk | \
        grep 'crypt' | \
        awk '{print $1}' | \
        sed 's/[^_\.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\-]//g'`
    )
    MAPPED_DEVICES_WITH_ENCRYPTION=()
    for item in "${MAPPED_BLOCK_DEVICES[@]}"; do
        check_item_in_set "$item" ${ENCRYPTED_PARTITION_LABELS[@]}
        if [ $? -ne 0 ]; then
            debug_msg "Ignoring mapped device ${DEFAULT['mapper-dir']}/$item. Not encrypted."
            continue
        fi
        debug_msg "Detected encrypted mapped device ${DEFAULT['mapper-dir']}/$item."
        MAPPED_DEVICES_WITH_ENCRYPTION=( ${MAPPED_DEVICES_WITH_ENCRYPTION[@]} "$item" )
    done; echo ${MAPPED_DEVICES_WITH_ENCRYPTION[@]}
    return 0
}

function fetch_all_available_device_partitions () {
    AVAILABLE_PARTITIONS=(
        `cat "${DEFAULT['partition-file']}" | \
            grep -v 'ram' | \
            grep -e '[0-9]$' | \
            awk '{print $NF}' | \
            sed 's/^/\/dev\//g'`
    )
    if [ ${#AVAILABLE_PARTITIONS[@]} -eq 0 ]; then
        error_msg "Could not detect any device partition."
        return 1
    fi
    echo "${AVAILABLE_PARTITIONS[@]}"
    return 0
}

function fetch_block_device_partition () {
    local BLOCK_DEVICE_PATH="$1"
    BLOCK_DEVICE=`echo "$BLOCK_DEVICE_PATH" | cut -d '/' -f3`
    IDENTIFIED_PARTITION=`lsblk | \
        grep "$BLOCK_DEVICE" | \
        grep 'part' | \
        awk '{print $1}'`
    if [ -z "$IDENTIFIED_PARTITION" ]; then
        echo; error_msg "No partition found on"\
            "block device ${RED}$BLOCK_DEVICE${RESET}."
        return 1
    fi
    local SANITIZED_PARTITION="${IDENTIFIED_PARTITION:2}"
    echo "$SANITIZED_PARTITION"
    return 0
}

function fetch_all_available_devices () {
    AVAILABLE_DEVS=(
        `lsblk | \
        grep -e '^[a-z].*' -e 'disk' | \
        awk '{print $1}' | \
        sed 's:^:/dev/:g'`
    )
    if [ ${#AVAILABLE_DEVS[@]} -eq 0 ]; then
        error_msg "Could not detect any devices connected to machine."
        return 1
    fi
    echo "${AVAILABLE_DEVS[@]}"
    return 0
}

function fetch_all_directory_files () {
    local DIR_PATH="$1"
    local DIRECTORY_FILE_PATHS=()
    for discovered_path in `find "$DIR_PATH"`; do
        if [[ "$discovered_path" == "$DIR_PATH" ]]; then
            continue
        fi
        local DIRECTORY_FILE_PATHS=( "${DIRECTORY_FILE_PATHS[@]}" "$discovered_path" )
    done
    echo ${DIRECTORY_FILE_PATHS[@]}
    return 0
}

function fetch_file_name_from_path () {
    local FILE_PATH="$1"
    basename "$FILE_PATH"
    return $?
}

function fetch_directory_from_file_path () {
    local FILE_PATH="$1"
    dirname "$FILE_PATH"
    return $?
}

function fetch_data_from_user () {
    local PROMPT="$1"
    local OPTIONAL="${@:2}"
    while :
    do
        if [[ $OPTIONAL == 'password' ]]; then
            read -sp "$PROMPT: " DATA
        else
            read -p "$PROMPT> " DATA
        fi
        if [ -z "$DATA" ]; then
            continue
        elif [[ "$DATA" == ".back" ]]; then
            return 1
        fi
        echo "$DATA"; break
    done
    return 0
}

function fetch_ultimatum_from_user () {
    PROMPT="$1"
    while :
    do
        local ANSWER=`fetch_data_from_user "$PROMPT"`
        case "$ANSWER" in
            'y' | 'Y' | 'yes' | 'Yes' | 'YES')
                return 0
                ;;
            'n' | 'N' | 'no' | 'No' | 'NO')
                return 1
                ;;
            *)
        esac
    done
    return 2
}

function fetch_selection_from_user () {
    local PROMPT="$1"
    local OPTIONS=( "${@:2}" "Back" )
    local OLD_PS3=$PS3
    PS3="$PROMPT> "
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Back')
                PS3="$OLD_PS3"
                return 1
                ;;
            *)
                local CHECK=`check_item_in_set "$opt" "${OPTIONS[@]}"`
                if [ $? -ne 0 ]; then
                    warning_msg "Invalid option."
                    continue
                fi
                PS3="$OLD_PS3"
                echo "$opt"
                return 0
                ;;
        esac
    done
    PS3="$OLD_PS3"
    return 2
}

function fetch_encryption_behaviour_description_by_label () {
    local LABEL="$1"
    check_valid_encryption_behaviour_label "$LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid encryption behaviour label"\
            "${RED}$LABEL${RESET}."
        return 1
    fi
    echo ${ENCRYPTION_BEHAVIOURS[$LABEL]}
    return 0
}

function fetch_decryption_behaviour_description_by_label () {
    local LABEL="$1"
    check_valid_decryption_behaviour_label "$LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid decryption behaviour label"\
            "${RED}$LABEL${RESET}."
        return 1
    fi
    echo ${DECRYPTION_BEHAVIOURS[$LABEL]}
    return 0
}

function fetch_checksum_algorithm_labels () {
    if [ ${#CHECKSUM_ALGORITHMS[@]} -eq 0 ]; then
        echo; error_msg "No ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}checksum algorithms${RESET} found."
        return 1
    fi
    echo ${!CHECKSUM_ALGORITHMS[@]}
    return 0
}

function fetch_checksum_command_by_label () {
    local LABEL="$1"
    check_valid_checksum_label "$LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid checksum algorithm label"\
            "${RED}$LABEL${RESET}."
        return 1
    fi
    echo ${CHECKSUM_ALGORITHMS[$LABEL]}
    return 0
}

function fetch_set_log_levels () {
    if [ ${#LOGGING_LEVELS[@]} -eq 0 ]; then
        echo; error_msg "No ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}logging levels${RESET} found."
        return 1
    fi
    echo ${LOGGING_LEVELS[@]}
    return 0
}

function fetch_decryption_behaviour_labels () {
    if [ ${#DECRYPTION_BEHAVIOURS[@]} -eq 0 ]; then
        echo; error_msg "No ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}decryption behaviours${RESET} found."
        return 1
    fi
    echo ${!DECRYPTION_BEHAVIOURS[@]}
    return 0
}

function fetch_encryption_behaviour_labels () {
    if [ ${#ENCRYPTION_BEHAVIOURS[@]} -eq 0 ]; then
        echo; error_msg "No ${YELLOW}$SCRIPT_NAME${RESET}"\
            "${RED}encryption behaviours${RESET} found."
        return 1
    fi
    echo ${!ENCRYPTION_BEHAVIOURS[@]}
    return 0
}

function fetch_decryption_command_aes256cbc () {
    local DECRYPT_TARGET_FILE="$1"
    local OUTPUT_FILE="$2"
    echo "openssl enc -aes-256-cbc -d -a -in $DECRYPT_TARGET_FILE -out $OUTPUT_FILE"
    return $?
}

function fetch_decryption_command_by_label () {
    local LABEL="$1"
    local ARGS="${@:2}"
    case "$LABEL" in
        'AES-256-CBC')
            fetch_decryption_command_aes256cbc $ARGS
            return $?
            ;;
        *)
            echo; error_msg "Invalid cryptosystem label ${RED}$LABEL${RESET}."\
                "Setting default to ${YELLOW}AES-256-CBC${RESET}."
            set_foxface_cryptosystem "aes-256-cbc"
            return 2
            ;;
    esac
    return 1
}

function fetch_encryption_command_aes256cbc () {
    local ENCRYPT_TARGET_FILE="$1"
    local OUTPUT_FILE="$2"
    echo "openssl enc -aes-256-cbc -salt -a -in $ENCRYPT_TARGET_FILE -out $OUTPUT_FILE"
    return $?
}

function fetch_encryption_command_by_label () {
    local LABEL="$1"
    local ARGS="${@:2}"
    case "$LABEL" in
        'AES-256-CBC')
            fetch_encryption_command_aes256cbc ${ARGS[@]}
            return $?
            ;;
        *)
            echo; error_msg "Invalid cryptosystem label ${RED}$LABEL${RESET}."\
                "Setting default to ${YELLOW}AES-256-CBC${RESET}."
            set_foxface_cryptosystem "aes-256-cbc"
            return 2
            ;;
    esac
    return 1
}

function fetch_foxface_encryption_label () {
    if [ -z "$FOXFACE_ENCRYPTION" ]; then
        return 1
    fi
    echo $FOXFACE_ENCRYPTION
    return 0
}

function fetch_valid_cryptosystem_labels () {
    if [ ${#FOXFACE_CRYPTOSYSTEMS[@]} -eq 0 ]; then
        return 1
    fi
    echo ${FOXFACE_CRYPTOSYSTEMS[@]}
    return 0
}

# SETTERS

function set_checksum_algorithm () {
    local ALGORITHM="$1"
    VALID_HASHING_ALGORITHMS=( `fetch_checksum_algorithm_labels` )
    check_item_in_set "$ALGORITHM" ${VALID_HASHING_ALGORITHMS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid checksum hashing algorithm ${RED}$ALGORITHM${RESET}."
        return 1
    fi
    FOXFACE_CHECKSUM="$ALGORITHM"
    return 0
}

function set_encryption_behaviour () {
    local BEHAVIOUR="$1"
    VALID_ENCRYPTION_BEHAVIOURS=( `fetch_encryption_behaviour_labels` )
    check_item_in_set "$BEHAVIOUR" ${VALID_ENCRYPTION_BEHAVIOURS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid encryption behaviour ${RED}$BEHAVIOUR${RESET}."
        return 1
    fi
    ENCRYPTION_BEHAVIOUR="$BEHAVIOUR"
    return 0
}

function set_decryption_behaviour () {
    local BEHAVIOUR="$1"
    VALID_DECRYPTION_BEHAVIOURS=( `fetch_decryption_behaviour_labels` )
    check_item_in_set "$BEHAVIOUR" ${VALID_DECRYPTION_BEHAVIOURS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid decryption behaviour ${RED}$BEHAVIOUR${RESET}."
        return 1
    fi
    DECRYPTION_BEHAVIOUR="$BEHAVIOUR"
    return 0
}

function set_auto_checksum () {
    local AUTO_CHECKSUM="$1"
    if [[ "$AUTO_CHECKSUM" != 'on' ]] && [[ "$AUTO_CHECKSUM" != 'off' ]]; then
        echo; error_msg "Invalid auto checksum value ${RED}$AUTO_CHECKSUM${RESET}."\
            "Defaulting to ${GREEN}ON${RESET}."
        FOXFACE_AUTO_CHECKSUM='on'
        return 1
    fi
    FOXFACE_AUTO_CHECKSUM=$AUTO_CHECKSUM
    return 0
}

function set_file_editor () {
    local FILE_EDITOR="$1"
    check_util_installed "$FILE_EDITOR"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Editor ${RED}$FILE_EDITOR${RESET} not installed."
        return 1
    fi
    DEFAULT['file-editor']=$FILE_EDITOR
    return 0
}

function set_foxface_logging () {
    local LOGGING="$1"
    if [[ "$LOGGING" != 'on' ]] && [[ "$LOGGING" != 'off' ]]; then
        echo; error_msg "Invalid logging value ${RED}$LOGGING${RESET}."\
            "Defaulting to ${GREEN}ON${RESET}."
        FOXFACE_LOGGING='on'
        return 1
    fi
    FOXFACE_LOGGING=$LOGGING
    return 0
}

function set_foxface_safety () {
    local SAFETY="$1"
    if [[ "$SAFETY" != 'on' ]] && [[ "$SAFETY" != 'off' ]]; then
        echo; error_msg "Invalid safety value ${RED}$SAFETY${RESET}."\
            "Defaulting to ${GREEN}ON${RESET}."
        FOXFACE_SAFETY='on'
        return 1
    fi
    FOXFACE_SAFETY=$SAFETY
    return 0
}

function set_temporary_file () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "File ${RED}$FILE_PATH${RESET} not found."
        return 1
    fi
    DEFAULT['tmp-file']="$FILE_PATH"
    return 0
}

function set_foxface_cryptosystem () {
    local LABEL="$1"
    check_is_supported_cryptosystem "$LABEL"
    if [ $? -ne 0 ]; then
        return 1
    fi
    FOXFACE_ENCRYPTION="$LABEL"
    return 0
}

# CHECKERS

function check_valid_mapped_block_device () {
    local MAPPED_DEVICE_PATH="$1"
    VALID_MAPPED_DEVICES=( `fetch_mapped_block_devices_with_encryption` )
    debug_msg "Valid mapped block devices ${VALID_MAPPED_DEVICES[@]}."
    MAPPED_DEVICE_LABEL=`basename "$MAPPED_DEVICE_PATH"`
    debug_msg "Mapped device label $MAPPED_DEVICE_LABEL."
    check_item_in_set "$MAPPED_DEVICE_LABEL" ${VALID_MAPPED_DEVICES[@]}
    if [ $? -ne 0 ]; then
        return 1
    fi
    return 0
}

function check_mapped_block_device_mountable () {
    local BLOCK_DEVICE="$1"
    local MOUNT_POINT_DIR_PATH="$2"
    check_directory_exists "$MOUNT_POINT_DIR_PATH"
    if [ $? -ne 0 ]; then
        mkdir "$MOUNT_POINT_DIR_PATH"
    fi
    info_msg "Checking device ${YELLOW}$BLOCK_DEVICE${RESET} is mountable..."
    mount_block_device "$BLOCK_DEVICE" "$MOUNT_POINT_DIR_PATH"
    if [ $? -ne 0 ]; then
        return 1
    fi
    unmount_block_device "$BLOCK_DEVICE"
    if [ $? -ne 0 ]; then
        return 2
    fi
    ok_msg "Mapped block device ${GREEN}$BLOCK_DEVICE${RESET} is mountable."
    remove_directory "$MOUNT_POINT_DIR_PATH"
    return 0
}

function check_valid_block_device_partition () {
    local TARGET_PART="$1"
    AVAILABLE_PARTITIONS=( `fetch_all_available_device_partitions` )
    debug_msg "Identified partitions: ${AVAILABLE_PARTITIONS[@]}."
    for AVAILABLE_PART in "${AVAILABLE_PARTITIONS[@]}"
    do
        if [[ "$TARGET_PART" == "$AVAILABLE_PART" ]]; then
            return 0
        fi
    done
    return 1
}

function check_valid_block_device () {
    local TARGET_DEV="$1"
    AVAILABLE_DEVICES=( `fetch_all_available_devices` )
    debug_msg "Identified devices: ${AVAILABLE_DEVICES[@]}."
    for AVAILABLE_DEV in "${AVAILABLE_DEVICES[@]}"
    do
        if [[ "$TARGET_DEV" == "$AVAILABLE_DEV" ]]; then
            return 0
        fi
    done
    return 1
}

function check_file_empty () {
    local FILE_PATH="$1"
    if [ ! -s "$FILE_PATH" ]; then
        return 0
    fi
    return 1
}

function check_directory_empty () {
    local DIR_PATH="$1"
    FILE_COUNT=`ls -a1 "$DIR_PATH" | grep -v '^.$' | grep -v '^..$' | wc -l`
    if [ $FILE_COUNT -eq 0 ]; then
        return 0
    fi
    return 1
}

function check_directory_exists () {
    local DIRECTORY_PATH="$1"
    if [ ! -d "$DIRECTORY_PATH" ]; then
        return 1
    fi
    return 0
}

function check_identical_strings () {
    local FIRST_STRING="$1"
    local SECOND_STRING="$2"
    if [[ "$FIRST_STRING" != "$SECOND_STRING" ]]; then
        return 1
    fi
    return 0
}

function check_file_exists () {
    local FILE_PATH="$1"
    if [ -f "$FILE_PATH" ]; then
        return 0
    fi
    return 1
}

function check_directory_exists () {
    local DIR_PATH="$1"
    if [ -d "$DIR_PATH" ]; then
        return 0
    fi
    return 1
}

function check_value_is_number () {
    local VALUE=$1
    test $VALUE -eq $VALUE &> /dev/null
    if [ $? -ne 0 ]; then
        return 1
    fi
    return 0
}

function check_checksum_is_valid () {
    local CHECKSUM="$1"
    local CHECKSUM_LENGTH_MAX="$2"
    local REGEX="$3"
    if [ -z "$CHECKSUM" ]; then
        echo; error_msg "No checksum specified."
        echo; return 3
    elif [ -z "$CHECKSUM_LENGTH_MAX" ]; then
        echo; error_msg "No maximum checksum length specified."
        echo; return 4
    elif [ -z "$REGEX" ]; then
        echo; error_msg "No checksum regex pattern specified."
        echo; return 5
    fi
    echo "$CHECKSUM" | egrep -e $REGEX &> /dev/null
    if [ $? -ne 0 ]; then
        debug_msg "Given checksum value $CHECKSUM does not corespond to"\
            "REGEX pattern $REGEX."
        return 1
    fi
    CHECKSUM_LENGTH=`echo "$CHECKSUM" | wc -c`
    debug_msg "Detected checksum length ($CHECKSUM_LENGTH)."
    CHECKSUM_LENGTH_MIN=$((CHECKSUM_LENGTH_MAX - 6))
    debug_msg "Computed error margin checksum length"\
        "floor value ($CHECKSUM_LENGTH_MIN characters)."
    if [ $CHECKSUM_LENGTH -le $CHECKSUM_LENGTH_MIN ] \
            || [ $CHECKSUM_LENGTH -gt $CHECKSUM_LENGTH_MAX ]; then
        debug_msg "Given checksum value ($CHECKSUM) does not corespond to"\
            "valid ($FOXFACE_CHECKSUM) hash length range"\
            "($CHECKSUM_LENGTH_MIN - $CHECKSUM_LENGTH_MAX characters)."
        return 2
    fi
    return 0
}

function check_valid_md5_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 36 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha1_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 44 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha256_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 68 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha512_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 132 '[a-zA-Z0-9]'
    return $?
}

function check_valid_checksum () {
    local CHECKSUM="$1"
    if [ -z "$FOXFACE_CHECKSUM" ]; then
        echo; error_msg "${BLUE}$SCRIPT_NAME${RESET} checksum"\
            "hashing algorithm not set."
        echo; return 1
    fi
    debug_msg "Detected $SCRIPT_NAME default checksum set to $FOXFACE_CHECKSUM."
    SANITIZED_CHECKSUM=`echo "$CHECKSUM" | sed -e 's/ //g' -e 's/-//g'`
    debug_msg "Original checksum $CHECKSUM sanitized to $SANITIZED_CHECKSUM."
    case "$FOXFACE_CHECKSUM" in
        'MD5')
            check_valid_md5_checksum "$CHECKSUM"
            ;;
        'SHA1')
            check_valid_sha1_checksum "$CHECKSUM"
            ;;
        'SHA256')
            check_valid_sha256_checksum "$CHECKSUM"
            ;;
        'SHA512')
            check_valid_sha512_checksum "$CHECKSUM"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET} checksum"\
                "algorithm set. Defaulting to ${CYAN}MD5${RESET}."
            set_checksum_algorithm "MD5"
            echo; return 2
            ;;
    esac
    return $?
}

function check_checksum_on () {
    if [[ "$FOXFACE_AUTO_CHECKSUM" != 'on' ]]; then
        return 1
    fi
    return 0
}

function check_checksum_off () {
    if [[ "$FOXFACE_AUTO_CHECKSUM" != 'off' ]]; then
        return 1
    fi
    return 0
}

function check_util_installed () {
    local UTIL_NAME="$1"
    type "$UTIL_NAME" &> /dev/null && return 0 || return 1
}

function check_valid_checksum_label () {
    local LABEL="$1"
    VALID_LABELS=( `fetch_checksum_algorithm_labels` )
    check_item_in_set "$LABEL" ${VALID_LABELS[@]}
    return $?
}

function check_valid_encryption_behaviour_label () {
    local LABEL="$1"
    VALID_LABELS=( `fetch_encryption_behaviour_labels` )
    check_item_in_set "$LABEL" ${VALID_LABELS[@]}
    return $?
}

function check_valid_decryption_behaviour_label () {
    local LABEL="$1"
    VALID_LABELS=( `fetch_decryption_behaviour_labels` )
    check_item_in_set "$LABEL" ${VALID_LABELS[@]}
    return $?
}

function check_loglevel_set () {
    local LOG_LEVEL="$1"
    LOG_LEVELS=( `fetch_set_log_levels` )
    check_item_in_set "$LOG_LEVEL" ${LOG_LEVELS[@]}
    return $?
}

function check_logging_on () {
    if [[ "$FOXFACE_LOGGING" != 'on' ]]; then
        return 1
    fi
    return 0
}

function check_logging_off () {
    if [[ "$FOXFACE_LOGGING" != 'off' ]]; then
        return 1
    fi
    return 0
}

function check_safety_on () {
    if [[ "$FOXFACE_SAFETY" != 'on' ]]; then
        return 1
    fi
    return 0
}

function check_safety_off () {
    if [[ "$FOXFACE_SAFETY" != 'off' ]]; then
        return 1
    fi
    return 0
}

function check_is_supported_cryptosystem () {
    local LABEL="$1"
    VALID_CRYPTOSYSTEMS=( `fetch_valid_cryptosystem_labels` )
    if [ $? -ne 0 ]; then
        echo; warning_msg "No supported ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}cryptosystems${RESET} found."
        return 2
    fi
    check_item_in_set "$LABEL" ${VALID_CRYPTOSYSTEMS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Illegal cryptosystem label ${RED}$LABEL${RESET}."
        return 1
    fi
    return 0
}

function check_util_installed () {
    local UTIL_NAME="$1"
    type "$UTIL_NAME" &> /dev/null && return 0 || return 1
}

function check_item_in_set () {
    local ITEM="$1"
    ITEM_SET=( "${@:2}" )
    for SET_ITEM in "${ITEM_SET[@]}"; do
        if [[ "$ITEM" == "$SET_ITEM" ]]; then
            return 0
        fi
    done
    return 1
}

# INSTALLERS

function apt_install_dependency() {
    local UTIL="$1"
    symbol_msg "${GREEN}+${RESET}" \
        "Installing package ${YELLOW}$UTIL${RESET}..."
    apt-get install $UTIL
    return $?
}

function apt_install_foxface_dependencies () {
    if [ ${#APT_DEPENDENCIES[@]} -eq 0 ]; then
        echo; info_msg 'No dependencies to fetch using the apt package manager.'
        return 1
    elif [ $EUID -ne 0 ]; then
        echo; warning_msg "${BLUE}$SCRIPT_NAME${RESET}"\
            "dependency install requires escalated privileges."
        info_msg "Try running ${YELLOW}$0${RESET} as root."
        return 2
    fi
    local FAILURE_COUNT=0
    echo; info_msg "Installing dependencies using apt package manager:"
    for package in "${APT_DEPENDENCIES[@]}"; do
        check_util_installed "$package"
        if [ $? -eq 0 ]; then
            ok_msg "${BLUE}$SCRIPT_NAME${RESET} dependency"\
                "${GREEN}$package${RESET} is already installed."
            continue
        fi
        echo; apt_install_dependency $package
        if [ $? -ne 0 ]; then
            nok_msg "Failed to install ${BLUE}$SCRIPT_NAME${RESET}"\
                "dependency ${RED}$package${RESET}!"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        else
            ok_msg "Successfully installed ${BLUE}$SCRIPT_NAME${RESET}"\
                "dependency ${GREEN}$package${RESET}."
            INSTALL_COUNT=$((INSTALL_COUNT + 1))
        fi
    done
    if [ $FAILURE_COUNT -ne 0 ]; then
        echo; warning_msg "${RED}$FAILURE_COUNT${RESET} dependency"\
            "installation failures!"\
            "Try installing the packages manually ${GREEN}:)${RESET}"
    fi
    return 0
}

# FORMATTERS

function format_universal_file_name () {
    local FILE_NAME="$1"
    SANITIZED_FILE_NAME=`echo "$FILE_NAME" | \
        sed -e 's/\.foxn//g' -e 's/\.foxy//g' -e 's/\.foxa//g'`
    CLEARTEXT_FILE_NAME="$SANITIZED_FILE_NAME.foxa"
    echo "$CLEARTEXT_FILE_NAME"
    return $?
}

function format_decrypted_file_name () {
    local FILE_NAME="$1"
    SANITIZED_FILE_NAME=`echo "$FILE_NAME" | \
        sed -e 's/\.foxn//g' -e 's/\.foxy//g' -e 's/\.foxa//g'`
    CLEARTEXT_FILE_NAME="$SANITIZED_FILE_NAME.foxn"
    echo "$CLEARTEXT_FILE_NAME"
    return $?
}

function format_encrypted_file_name () {
    local FILE_NAME="$1"
    SANITIZED_FILE_NAME=`echo "$FILE_NAME" | \
        sed -e 's/\.foxn//g' -e 's/\.foxy//g' -e 's/\.foxa//g'`
    CIPHERTEXT_FILE_NAME="$SANITIZED_FILE_NAME.foxy"
    echo "$CIPHERTEXT_FILE_NAME"
    return $?
}

function format_flag_colors () {
    local FLAG="$1"
    case "$FLAG" in
        'on')
            local DISPLAY="${GREEN}ON${RESET}"
            ;;
        'off')
            local DISPLAY="${RED}OFF${RESET}"
            ;;
        *)
            local DISPLAY=$FLAG
            ;;
    esac; echo $DISPLAY
    return 0
}

function format_description () {
    local DESCRIPTION="$@"
    if [ -z "$DESCRIPTION" ]; then
        echo; error_msg "No description specified."
        return 1
    fi
    IFS='.'
    for line in $DESCRIPTION; do
        if [[ "${line::1}" == ' ' ]]; then
            DISPLAY_LINE=${line:1}
        else
            DISPLAY_LINE=$line
        fi
        echo "  $DISPLAY_LINE."
    done
    IFS=' '
    return 0
}

# GENERAL

function luks_decrypt_device_partition () {
    local DEVICE_PARTITION="$1"
    debug_msg "Device partition is $DEVICE_PARTITION."

    while :
    do
        echo; info_msg "Type encrypted block device label to be used as"\
            "identifier and mount point, or ${MAGENTA}.back${RESET}."
        DEVICE_LABEL=`fetch_data_from_user "DeviceLabel"`
        if [ $? -ne 0 ]; then
            return 1
        fi
        debug_msg "Device label fetched from user is $DEVICE_LABEL."
        break
    done

    local BLOCK_DEVICE=${DEVICE_PARTITION::-1}
    debug_msg "Block device is $BLOCK_DEVICE."

    echo; create_mapped_partition_mountpoint_directory "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then
        debug_msg "Could not create mapped partition mount point directory"\
            "${DEFAULT['mount-dir']}/$DEVICE_LABEL."
        return 2
    fi

    create_mapper_from_block_device_partition "$DEVICE_PARTITION" "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then
        debug_msg "Failed decrypt block device partition $DEVICE_PARTITION."
        return 3
    fi

    mount_block_device "${DEFAULT['mapper-dir']}/$DEVICE_LABEL" \
        "${DEFAULT['mount-dir']}/$DEVICE_LABEL"
    if [ $? -ne 0 ]; then
        debug_msg "Failed to mount mapped object"\
            "${DEFAULT['mapper-dir']}/$DEVICE_LABEL"\
            "to ${DEFAULT['mount-dir']}/$DEVICE_LABEL."
        return 4
    fi
    return 0
}

function mount_block_device () {
    local BLOCK_DEVICE="$1"
    local MOUNT_POINT_DIR_PATH="$2"
    mount "$BLOCK_DEVICE" "$MOUNT_POINT_DIR_PATH" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not mount ${YELLOW}$BLOCK_DEVICE${RESET}"\
            "on ${RED}$MOUNT_POINT_DIR_PATH${RESET}."
        return 1
    fi
    ok_msg "Successfully mounted ${YELLOW}$BLOCK_DEVICE${RESET}"\
        "on ${GREEN}$MOUNT_POINT_DIR_PATH${RESET}."
    return 0
}

function unmount_block_device () {
    local BLOCK_DEVICE="$1"
    umount "$BLOCK_DEVICE" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not unmount ${RED}$BLOCK_DEVICE${RESET}."
        return 1
    fi
    ok_msg "Successfully unmounted ${GREEN}$BLOCK_DEVICE${RESET}."
    return 0
}

function create_mapper_from_block_device_partition () {
    local DEVICE_PARTITION="$1"
    local DEVICE_LABEL="$2"
    info_msg "Decrypting device partition ${YELLOW}$DEVICE_PARTITION${RESET}"\
        "to ${DEFAULT['mapper-dir']}/$DEVICE_LABEL..."
    echo; cryptsetup luksOpen "$DEVICE_PARTITION" "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not decrypt device partition ${RED}$DEVICE_PARTITION${RESET}"\
            "to ${RED}${DEFAULT['mapper-dir']}/$DEVICE_LABEL${RESET}."
        return 1
    fi
    echo; ok_msg "Successfully decrypted device partition"\
        "${CYAN}$DEVICE_PARTITION${RESET}"\
        "to ${GREEN}${DEFAULT['mapper-dir']}/$DEVICE_LABEL${RESET}."
    return 0
}

function create_vfat_file_system_on_mapped_partition () {
    local DEVICE_PARTITION="$1"
    local DEVICE_LABEL="$2"
    info_msg "Creating ${CYAN}VFAT${RESET} file system on mapped partition"\
        "${YELLOW}${DEFAULT['mapper-dir']}/$DEVICE_LABEL${RESET}..."
    mkfs -t vfat "${DEFAULT['mapper-dir']}/$DEVICE_LABEL" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not create ${CYAN}VFAT${RESET}"\
            "file system on ${CYAN}$DEVICE_ENCRYPTION${RESET}"\
            "mapped block device partition ${YELLOW}$DEVICE_PARTITION${RESET}."
        return 1
    fi
    ok_msg "Successfully created ${CYAN}VFAT${RESET} file system on"\
        "${CYAN}$DEVICE_ENCRYPTION${RESET} mapped"\
        "block device partition ${GREEN}$DEVICE_PARTITION${RESET}."
    return 0
}

function create_mapped_partition_mountpoint_directory () {
    info_msg "Creating mount point directory"\
        "${YELLOW}${DEFAULT['mount-dir']}/$DEVICE_LABEL${RESET}."
    mkdir -p "${DEFAULT['mount-dir']}/$DEVICE_LABEL" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not create mount point directory"\
            "${RED}${DEFAULT['mount-dir']}/$DEVICE_LABEL${RESET}."
        return 1
    fi
    ok_msg "Successfully created mount point directory"\
        "${GREEN}${DEFAULT['mount-dir']}/$DEVICE_LABEL${RESET}."
    return 0
}

function close_block_device_partition_mapper () {
    local MAPPED_BLOCK_DEVICE="$1"
    cryptsetup luksClose "$MAPPED_BLOCK_DEVICE" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not close block device ${RED}$MAPPED_BLOCK_DEVICE${RESET}"\
            "${CYAN}$DEVICE_ENCRYPTION${RESET} mapper."
        return 1
    fi
    ok_msg "Successfully closed block device"\
        "${GREEN}$MAPPED_BLOCK_DEVICE${RESET}"\
        "${CYAN}$DEVICE_ENCRYPTION${RESET} mapper."
    return 0
}

function luks_encrypt_device_partition () {
    local DEVICE_PARTITION="$1"
    info_msg "Encrypting partition ${YELLOW}$DEVICE_PARTITION${RESET}"\
        "using ${CYAN}$DEVICE_ENCRYPTION${RESET}..."
    echo; cryptsetup --verbose --verify-passphrase luksFormat "$DEVICE_PARTITION"
    while :
    do
        echo; info_msg "Type encrypted block device label"\
            "or ${MAGENTA}.back${RESET}."
        DEVICE_LABEL=`fetch_data_from_user "DeviceLabel"`
        if [ $? -ne 0 ]; then
            return 1
        fi; break
    done
    echo; create_mapper_from_block_device_partition "$DEVICE_PARTITION" "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then return 2; fi
    create_vfat_file_system_on_mapped_partition "$DEVICE_PARTITION" "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then return 3; fi
    e2label "${DEFAULT['mapper-dir']}/$DEVICE_LABEL" "$DEVICE_LABEL" &> /dev/null
    create_mapped_partition_mountpoint_directory "$DEVICE_LABEL"
    if [ $? -ne 0 ]; then return 4; fi
    check_mapped_block_device_mountable "${DEFAULT['mapper-dir']}/$DEVICE_LABEL" \
        "${DEFAULT['mount-dir']}/$DEVICE_LABEL"
    close_block_device_partition_mapper "${DEFAULT['mapper-dir']}/$DEVICE_LABEL"
    if [ $? -ne 0 ]; then return 5; fi
    return 0
}

function create_partition_on_block_device () {
    local BLOCK_DEVICE="$1"
    check_valid_block_device "$BLOCK_DEVICE"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid block device ${RED}$BLOCK_DEVICE${RESET}."
        return 1
    fi
    fdisk "$BLOCK_DEVICE"
    EXIT_CODE=$?
    info_msg "Informing the OS of partition table changes..."
    partprobe; return $EXIT_CODE
}

function remove_directory () {
    local DIR_PATH="$1"
    check_directory_exists "$DIR_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid directory path ${RED}$DIR_PATH${RESET}."
        return 1
    fi
    find "$DIR_PATH" -type f | xargs shred f -n 10 -z -u &> /dev/null
    rm -rf "$DIR_PATH" &> /dev/null
    return $?
}

function remove_file () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid file path ${RED}$FILE_PATH${RESET}."
        return 1
    fi
    shred -f -n 10 -z -u "$FILE_PATH" &> /dev/null
    rm -f "$FILE_PATH" &> /dev/null
    return $?
}

function archive_file () {
    local FILE_PATH="$1"
    local OUT_FILE_PATH="$2"
    tar -cf "$OUT_FILE_PATH" "$FILE_PATH" &> /dev/null
    return $?
}

function write_to_file () {
    local WRITTER_MODE="$1"
    local TARGET_FILE_PATH="$2"
    local DATA="${@:3}"
    case "$WRITTER_MODE" in
        'append')
            echo "$DATA" >> "$TARGET_FILE_PATH"
            ;;
        'override')
            echo "$DATA" > "$TARGET_FILE_PATH"
            ;;
        *)
            echo; error_msg "Invalid file writter mode"\
                "${RED}$WRITTER_MODE${RESET}."
            ;;
    esac
    return $?
}

function clone_directory_structure () {
    local SOURCE_DIR_PATH="$1"
    local TARGET_DIR_PATH="$2"
    cp -r "$SOURCE_DIR_PATH" "$TARGET_DIR_PATH" &> /dev/null
    if [ ! -d "$TARGET_DIR_PATH" ]; then
        echo; error_msg "Something went wrong. Could not clone directory"\
            "structure of ${YELLOW}$SOURCE_DIR_PATH${RESET}"\
            "to ${RED}$TARGET_DIR_PATH${RESET}."
        return 1
    fi
    for discovered_path in `find "$TARGET_DIR_PATH"`; do
        check_file_exists "$discovered_path"
        if [ $? -ne 0 ]; then
            continue
        fi
        rm $discovered_path &> /dev/null
    done
    return 0
}

function three_second_delay () {
    for item in `seq 3`; do
        echo -n '.'; sleep 1
    done
    return 0
}

function create_data_checksum () {
    local DATA="$@"
    echo "$DATA" | ${CHECKSUM_ALGORITHMS[$FOXFACE_CHECKSUM]}
    return $?
}

function create_file_checksum () {
    local FILE_PATH="$1"
    ${CHECKSUM_ALGORITHMS[$FOXFACE_CHECKSUM]} "$FILE_PATH" | awk '{print $1}'
    return $?
}

function create_directory_checksum () {
    local DIR_PATH="$1"
    tar -cf - "$DIR_PATH" &> /dev/null | \
        ${CHECKSUM_ALGORITHMS[$FOXFACE_CHECKSUM]} | \
        awk '{print $1}'
    return $?
}

function log_message () {
    local LOG_LEVEL="$1"
    local OPTIONAL="$2"
    local MSG="${@:3}"
    check_logging_on
    if [ $? -ne 0 ]; then
        return 1
    fi
    check_loglevel_set "$LOG_LEVEL"
    if [ $? -ne 0 ]; then
        return 2
    fi
    case "$LOG_LEVEL" in
        'SYMBOL')
            echo "${MAGENTA}`date`${RESET} - [ $OPTIONAL ]: $MSG" >> ${DEFAULT['log-file']}
            ;;
        *)
            echo "${MAGENTA}`date`${RESET} - [ $LOG_LEVEL ]: $MSG" >> ${DEFAULT['log-file']}
            ;;
    esac
    return $?
}

function encrypt_aes_256_cbc () {
    # [ NOTE ]: Uses openssl aes 256 cbc encryption
    # [ NOTE ]: Salts it with password
    local ENCRYPT_TARGET_FILE="${1:--}"
    local OUTPUT_FILE="${2:--}"
    LABEL=`fetch_foxface_encryption_label`
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not fetch ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}cryptosystem label${RESET}."
        return 1
    fi
    COMMAND=`fetch_encryption_command_by_label \
        "$LABEL" "$ENCRYPT_TARGET_FILE" "$OUTPUT_FILE"`
    debug_msg "File encryption command ($COMMAND)."
    info_msg "Encrypting ${YELLOW}$ENCRYPT_TARGET_FILE${RESET}"\
        "using ${CYAN}$LABEL${RESET}..."
    $COMMAND &> /dev/null; return $?
}

function decrypt_aes_256_cbc () {
    # [ NOTE ]: Uses openssl aes 256 cbc decryption
    local DECRYPT_TARGET_FILE="${1:--}"
    local OUTPUT_FILE="${2:--}"
    LABEL=`fetch_foxface_encryption_label`
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not fetch ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}cryptosystem label${RESET}."
        return 1
    fi
    COMMAND=`fetch_decryption_command_by_label \
        "$LABEL" "$DECRYPT_TARGET_FILE" "$OUTPUT_FILE"`
    debug_msg "File decryption command ($COMMAND)."
    info_msg "Decrypting ${YELLOW}$DECRYPT_TARGET_FILE${RESET}"\
        "using ${CYAN}$LABEL${RESET}..."
    $COMMAND &> /dev/null; return $?
}

# ACTIONS
# [ NOTE ]: Safety flag verifications are performed here.

function action_unmount_encrypted_block_device () {
    local MAPPED_DEVICE_PATH="$1"
    if [ $EUID -ne 0 ]; then
        echo; warning_msg "Block device unmount requires"\
            "elevated privileges. Try running ${YELLOW}$0${RESET} as root."
        return 2
    fi
    debug_msg "Current user passed elevated privilege check."
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Block device ${RED}$MAPPED_DEVICE_PATH${RESET}"\
            "will not be unmounted."
        return 1
    fi
    debug_msg "$SCRIPT_NAME passed safety check."
    unmount_block_device "$MAPPED_DEVICE_PATH"
    if [ $? -ne 0 ]; then
        return 3
    fi
    close_block_device_partition_mapper "$MAPPED_DEVICE_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        nok_msg "Could not unmount encrypted block device"\
            "${RED}$MAPPED_DEVICE_PATH${RESET}"
        return 4
    fi
    MAPPED_DEVICE_LABEL=`basename "$MAPPED_DEVICE_PATH"`
    debug_msg "Fetched device label $MAPPED_DEVICE_LABEL"\
        "from device path $MAPPED_DEVICE_PATH."
    check_directory_exists "${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL"
    if [ $? -eq 0 ]; then
        debug_msg "Detected mount point directory"\
            "${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL."
        remove_directory "${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL"
        if [ $? -ne 0 ]; then
            warning_msg "Something went wrong."\
                "Could not remove mount point directory"\
                "${RED}${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL${RESET}."
        else
            ok_msg "Successfully remove mount point directory"\
                "${GREEN}${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL${RESET}"
        fi
    else
        debug_msg "No mount point directory detected at"\
            "${DEFAULT['mount-dir']}/$MAPPED_DEVICE_LABEL."
    fi
    ok_msg "Successfully unmounted block device"\
        "${GREEN}$MAPPED_DEVICE_PATH${RESET}."
    return $EXIT_CODE
}

function action_decrypt_block_device () {
    local BLOCK_DEVICE_PARTITION="$1"
    if [ $EUID -ne 0 ]; then
        echo; warning_msg "Block device decryption procedures require"\
            "elevated privileges. Try running ${YELLOW}$0${RESET} as root."
        return 1
    fi
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Block device ${RED}$BLOCK_DEVICE${RESET} will not be decrypted."
        return 1
    fi
    luks_decrypt_device_partition "$DEVICE_PARTITION"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not decrypting device partition"\
            "${RED}$DEVICE_PARTITION${RESET}."
        return 3
    fi
    echo; ok_msg "Successfully decrypted block device partition"\
        "${GREEN}$DEVICE_PARTITION${RESET} using"\
        "${CYAN}$DEVICE_ENCRYPTION${RESET}."
    return 0
}

function action_encrypt_block_device () {
    local BLOCK_DEVICE="$1"
    if [ $EUID -ne 0 ]; then
        echo; warning_msg "Block device encryption procedures require"\
            "elevated privileges. Try running ${YELLOW}$0${RESET} as root."
        return 1
    fi
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Block device ${RED}$BLOCK_DEVICE${RESET} will not be encrypted."
        return 1
    fi

    echo; info_msg "Create partition on ${YELLOW}$BLOCK_DEVICE${RESET}..."
    echo; symbol_msg "${BLUE}ProTip${RESET}" "Try using the following"\
        "${CYAN}fdisk${RESET} commands ${GREEN}n-p-w${RESET}.
${CYAN}n${RESET} - Add new partition
${CYAN}p${RESET} - Make it primary partition
${CYAN}w${RESET} - Write table to disk"
    create_partition_on_block_device "$BLOCK_DEVICE"

    DEVICE_PARTITION=`fetch_block_device_partition "$BLOCK_DEVICE"`
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not fetch block device"\
            "${RED}$BLOCK_DEVICE${RESET} partition."
        return 2
    fi

    luks_encrypt_device_partition "/dev/$DEVICE_PARTITION"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not encrypting device partition"\
            "${RED}/dev/$DEVICE_PARTITION${RESET}."
        return 3
    fi
    echo; ok_msg "Successfully encrypted block device partition"\
        "${GREEN}/dev/$DEVICE_PARTITION${RESET} using"\
        "${CYAN}$DEVICE_ENCRYPTION${RESET}."
    return 0
}

function action_clear_log_file () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "will not be cleared."
        return 3
    fi
    echo -n > "${DEFAULT['log-file']}"
    check_file_empty "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not clear ${BLUE}$SCRIPT_NAME${RESET}"\
            "log file ${RED}${DEFAULT['log-file']}${RESET}."
        return 4
    fi
    echo; ok_msg "Successfully cleared ${BLUE}$SCRIPT_NAME${RESET}"\
        "log file ${GREEN}${DEFAULT['log-file']}${RESET}."
    return 0
}

function action_log_view_tail () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; tail -n ${DEFAULT['log-lines']} ${DEFAULT['log-file']}
    return $?
}

function action_log_view_head () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; head -n ${DEFAULT['log-lines']} ${DEFAULT['log-file']}
    return $?
}

function action_log_view_more () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; more ${DEFAULT['log-file']}
    return $?
}

function action_encrypt_directory () {
    local DIRECTORY_PATH="$1"
    debug_msg "Directory to encrypt ($DIRECTORY_PATH)."\
        "Detected encryption behaviour set ($ENCRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Directory ${RED}$DIRECTORY_PATH${RESET} will not be encrypted."
        return 1
    fi
    case "$ENCRYPTION_BEHAVIOUR" in
        'Replace')
            handle_encryption_behaviour_pattern_replace 'directory' "$DIRECTORY_PATH"
            ;;
        'Mirror')
            handle_encryption_behaviour_pattern_mirror 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive')
            handle_encryption_behaviour_pattern_archive 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive-Replace')
            handle_encryption_behaviour_pattern_archive_replace 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive-Mirror')
            handle_encryption_behaviour_pattern_archive_mirror 'directory' "$DIRECTORY_PATH"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "encryption behaviour pattern"\
                "${RED}$ENCRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_encrypt_string () {
    local CLEARTEXT="$@"
    debug_msg "String to encrypt ($CLEARTEXT)."\
        "Detected encryption behaviour set ($ENCRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Given data will not be encrypted."
        return 1
    fi
    case "$ENCRYPTION_BEHAVIOUR" in
        'Replace')
            handle_encryption_behaviour_pattern_replace 'cleartext' "$CLEARTEXT"
            ;;
        'Mirror')
            handle_encryption_behaviour_pattern_mirror 'cleartext' "$CLEARTEXT"
            ;;
        'Archive')
            handle_encryption_behaviour_pattern_archive 'cleartext' "$CLEARTEXT"
            ;;
        'Archive-Replace')
            handle_encryption_behaviour_pattern_archive_replace 'cleartext' "$CLEARTEXT"
            ;;
        'Archive-Mirror')
            handle_encryption_behaviour_pattern_archive_mirror 'cleartext' "$CLEARTEXT"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "encryption behaviour pattern"\
                "${RED}$ENCRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_decrypt_directory () {
    local DIRECTORY_PATH="$1"
    debug_msg "Directory to decrypt ($DIRECTORY_PATH)."\
        "Detected decryption behaviour set ($DECRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Directory ${RED}$DIRECTORY_PATH${RESET} will not be decrypted."
        return 1
    fi
    case "$DECRYPTION_BEHAVIOUR" in
        'Replace')
            handle_decryption_behaviour_pattern_replace 'directory' "$DIRECTORY_PATH"
            ;;
        'Mirror')
            handle_decryption_behaviour_pattern_mirror 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive')
            handle_decryption_behaviour_pattern_archive 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive-Replace')
            handle_decryption_behaviour_pattern_archive_replace 'directory' "$DIRECTORY_PATH"
            ;;
        'Archive-Mirror')
            handle_decryption_behaviour_pattern_archive_mirror 'directory' "$DIRECTORY_PATH"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "decryption behaviour pattern"\
                "${RED}$DECRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_decrypt_string () {
    local CIPHERTEXT="$@"
    debug_msg "String to decrypt ($CIPHERTEXT)."\
        "Detected decryption behaviour set ($DECRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Given data will not be decrypted."
        return 1
    fi
    case "$DECRYPTION_BEHAVIOUR" in
        'Replace')
            handle_decryption_behaviour_pattern_replace 'ciphertext' "$CIPHERTEXT"
            ;;
        'Mirror')
            handle_decryption_behaviour_pattern_mirror 'ciphertext' "$CIPHERTEXT"
            ;;
        'Archive')
            handle_decryption_behaviour_pattern_archive 'ciphertext' "$CIPHERTEXT"
            ;;
        'Archive-Replace')
            handle_decryption_behaviour_pattern_archive_replace 'ciphertext' "$CIPHERTEXT"
            ;;
        'Archive-Mirror')
            handle_decryption_behaviour_pattern_archive_mirror 'ciphertext' "$CIPHERTEXT"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "decryption behaviour pattern"\
                "${RED}$DECRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_decrypt_file () {
    local FILE_PATH="$1"
    debug_msg "File to decrypt ($FILE_PATH)."\
        "Detected decryption behaviour set ($DECRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "File ${RED}$FILE_PATH${RESET} will not be decrypted."
        return 1
    fi
    case "$DECRYPTION_BEHAVIOUR" in
        'Replace')
            handle_decryption_behaviour_pattern_replace 'file' "$FILE_PATH"
            ;;
        'Mirror')
            handle_decryption_behaviour_pattern_mirror 'file' "$FILE_PATH"
            ;;
        'Archive')
            handle_decryption_behaviour_pattern_archive 'file' "$FILE_PATH"
            ;;
        'Archive-Replace')
            handle_decryption_behaviour_pattern_archive_replace 'file' "$FILE_PATH"
            ;;
        'Archive-Mirror')
            handle_decryption_behaviour_pattern_archive_mirror 'file' "$FILE_PATH"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "decryption behaviour pattern"\
                "${RED}$DECRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_encrypt_file () {
    local FILE_PATH="$1"
    debug_msg "File to encrypt ($FILE_PATH)."\
        "Detected encryption behaviour set ($ENCRYPTION_BEHAVIOUR)."

    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "File ${RED}$FILE_PATH${RESET} will not be encrypted."
        return 1
    fi
    case "$ENCRYPTION_BEHAVIOUR" in
        'Replace')
            handle_encryption_behaviour_pattern_replace 'file' "$FILE_PATH"
            ;;
        'Mirror')
            handle_encryption_behaviour_pattern_mirror 'file' "$FILE_PATH"
            ;;
        'Archive')
            handle_encryption_behaviour_pattern_archive 'file' "$FILE_PATH"
            ;;
        'Archive-Replace')
            handle_encryption_behaviour_pattern_archive_replace 'file' "$FILE_PATH"
            ;;
        'Archive-Mirror')
            handle_encryption_behaviour_pattern_archive_mirror 'file' "$FILE_PATH"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET}"\
                "encryption behaviour pattern"\
                "${RED}$ENCRYPTION_BEHAVIOUR${RESET}."
            return 1
    esac
    return $?
}

function action_create_checksum_of_string () {
    local STRING_TO_HASH="$@"
    DATA_CHECKSUM=`create_data_checksum "$STRING_TO_HASH"`
    EXIT_CODE=$?
    echo; symbol_msg "${CYAN}$FOXFACE_CHECKSUM${RESET}" \
        "${GREEN}$DATA_CHECKSUM${RESET}"
    if [ $EXIT_CODE -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not create ${CYAN}$FOXFACE_CHECKSUM${RESET} checksum"\
            "from given data: ${RED}$STRING_TO_HASH${RESET}."
        return $EXIT_CODE
    fi
    ok_msg "Successfully computed given data"\
        "${CYAN}$FOXFACE_CHECKSUM${RESET} checksum."
    return $EXIT_CODE
}

function action_create_checksum_of_file () {
    local FILE_PATH="$1"
    FILE_CHECKSUM=`create_file_checksum "$FILE_PATH"`
    EXIT_CODE=$?
    echo; symbol_msg "${CYAN}$FOXFACE_CHECKSUM${RESET}" \
        "${GREEN}$FILE_CHECKSUM${RESET}"
    if [ $EXIT_CODE -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not create ${RED}$FILE_PATH${RESET} file"\
            "${CYAN}$FOXFACE_CHECKSUM${RESET} checksum."
        return $EXIT_CODE
    fi
    ok_msg "Successfully computed ${GREEN}$FILE_PATH${RESET} file"\
        "${CYAN}$FOXFACE_CHECKSUM${RESET} checksum."
    return $EXIT_CODE
}

function action_compare_checksum_of_string () {
    local STRING_CHECKSUM="$1"
    local STRING_TO_COMPARE="$2"
    VALID_CHECKSUM=`create_data_checksum "$STRING_TO_COMPARE"`
    SANITIZED_CHECKSUM=`echo "$STRING_CHECKSUM" | sed -e 's/ //g' -e 's/-//g'`
    SANITIZED_VALID_CHECKSUM=`echo "$VALID_CHECKSUM" | sed -e 's/ //g' -e 's/-//g'`
    debug_msg "$STRING_CHECKSUM - $STRING_TO_COMPARE - $VALID_CHECKSUM -"\
        "$SANITIZED_CHECKSUM - $SANITIZED_VALID_CHECKSUM"
    check_identical_strings "$SANITIZED_CHECKSUM" "$SANITIZED_VALID_CHECKSUM"
    if [ $? -ne 0 ]; then
        echo; nok_msg "${CYAN}$FOXFACE_CHECKSUM${RESET} checksum of"\
            "given data is ${YELLOW}$SANITIZED_VALID_CHECKSUM${RESET} not"\
            "${RED}$STRING_CHECKSUM${RESET}."
        return 2
    fi
    echo; ok_msg "It's a match! Given data ${CYAN}$FOXFACE_CHECKSUM${RESET}"\
        "checksum is ${GREEN}$STRING_CHECKSUM${RESET}."
    return 0
}

function action_compare_checksum_of_file () {
    local FILE_PATH="$1"
    local FILE_CHECKSUM="$2"
    VALID_CHECKSUM=`create_file_checksum "$FILE_PATH"`
    SANITIZED_CHECKSUM=`echo "$FILE_CHECKSUM | sed -e 's/ //g' -e 's/-//g'"`
    SANITIZED_VALID_CHECKSUM=`echo "$VALID_CHECKSUM | sed -e 's/ //g' -e 's/-//g'"`
    check_identical_strings "$SANITIZED_CHECKSUM" "$SANITIZED_VALID_CHECKSUM"
    if [ $? -ne 0 ]; then
        echo; nok_msg "$FOXFACE_CHECKSUM checksum of"\
            "${YELLOW}$FILE_PATH${RESET} is $FILE_CHECKSUM not"\
            "${RED}$CHECKSUM${RESET}."
        return 2
    fi
    echo; ok_msg "It's a match! ${YELLOW}$FILE_PATH${RESET}"\
        "file ${CYAN}$FOXFACE_CHECKSUM${RESET}"\
        "checksum is ${GREEN}$CHECKSUM${RESET}."
    return 0
}

function action_set_encryption_algorithm () {
    VALID_ENCRYPTION_ALGORITHMS=( `fetch_valid_cryptosystem_labels` )
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch encryption algorithm labels."
        return 2
    fi
    while :
    do
        echo; info_msg "Select ${BLUE}$SCRIPT_NAME${RESET} encryption algorithm."; echo
        ENCRYPTION_ALGORITHM=`fetch_selection_from_user "CryptoSystem" ${VALID_ENCRYPTION_ALGORITHMS[@]}`
        if [ $? -ne 0 ]; then
            return 1
        fi
        set_foxface_cryptosystem "$ENCRYPTION_ALGORITHM"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Something went wrong."\
                "Could not set encryption algorithm"\
                "${RED}$ENCRYPTION_ALGORITHM${RESET}."
            return 3
        fi
        echo; info_msg "Setting ${BLUE}$SCRIPT_NAME${RESET} encryption algorithm to"\
            "${YELLOW}$ENCRYPTION_ALGORITHM${RESET}."
        echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
        if [ $? -ne 0 ]; then
            continue
        fi
        break
    done
    ok_msg "Successfully set encryption algorithm"\
        "${GREEN}$ENCRYPTION_ALGORITHM${RESET}."
    return 0
}

function action_set_hashing_algorithm () {
    VALID_HASHING_ALGORITHMS=( `fetch_checksum_algorithm_labels` )
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch hashing algorithm labels."
        return 2
    fi
    while :
    do
        echo; info_msg "Select ${BLUE}$SCRIPT_NAME${RESET} hashing algorithm."; echo
        HASHING_ALGORITHM=`fetch_selection_from_user "HashAlgorithm" ${VALID_HASHING_ALGORITHMS[@]}`
        if [ $? -ne 0 ]; then
            return 1
        fi
        set_checksum_algorithm "$HASHING_ALGORITHM"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Something went wrong."\
                "Could not set checksum hashing algorithm"\
                "${RED}$HASHING_ALGORITHM${RESET}."
            return 3
        fi
        echo; info_msg "Setting checksum hashing algorithm to"\
            "${YELLOW}$HASHING_ALGORITHM${RESET}."
        echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
        if [ $? -ne 0 ]; then
            continue
        fi
        break
    done
    ok_msg "Successfully set checksum hashing algorithm"\
        "${GREEN}$HASHING_ALGORITHM${RESET}."
    return 0
}

function action_set_encryption_behaviour () {
    VALID_ENCRYPTION_BEHAVIOURS=( `fetch_encryption_behaviour_labels` )
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch encryption behaviour labels."
        return 2
    fi
    while :
    do
        echo; info_msg "Select ${BLUE}$SCRIPT_NAME${RESET} behaviour upon encryption."; echo
        BEHAVIOUR=`fetch_selection_from_user "Behaviour" ${VALID_ENCRYPTION_BEHAVIOURS[@]}`
        if [ $? -ne 0 ]; then
            return 1
        fi
        set_encryption_behaviour "$BEHAVIOUR"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Something went wrong."\
                "Could not set encryption behaviour ${RED}$BEHAVIOUR${RESET}."
            return 3
        fi
        echo; symbol_msg "${BLUE}$BEHAVIOUR${RESET}" "Description:"
        echo; display_behaviour_description "encryption" "$BEHAVIOUR"
        echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
        if [ $? -ne 0 ]; then
            continue
        fi
        break
    done
    ok_msg "Successfully set encryption behaviour"\
        "${GREEN}$BEHAVIOUR${RESET}."
    return 0
}

function action_set_decryption_behaviour () {
    VALID_DECRYPTION_BEHAVIOURS=( `fetch_decryption_behaviour_labels` )
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch decryption behaviour labels."
        return 2
    fi
    while :
    do
        echo; info_msg "Select ${BLUE}$SCRIPT_NAME${RESET} behaviour upon decryption."; echo
        BEHAVIOUR=`fetch_selection_from_user "Behaviour" ${VALID_DECRYPTION_BEHAVIOURS[@]}`
        if [ $? -ne 0 ]; then
            return 1
        fi
        set_decryption_behaviour "$BEHAVIOUR"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Something went wrong."\
                "Could not set decryption behaviour ${RED}$BEHAVIOUR${RESET}."
            return 3
        fi
        echo; symbol_msg "${BLUE}$BEHAVIOUR${RESET}" "Description:"
        echo; display_behaviour_description "decryption" "$BEHAVIOUR"
        echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
        if [ $? -ne 0 ]; then
            continue
        fi
        break
    done
    ok_msg "Successfully set encryption behaviour"\
        "${GREEN}$BEHAVIOUR${RESET}."
    return 0
}

function action_set_auto_checksum_on () {
    check_checksum_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} auto checksum"\
            "already is ${GREEN}ON${RESET}."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_auto_checksum 'on'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} auto checksum"\
            "to ${GREEN}ON${RESET}."
        return 3
    fi
    ok_msg "Auto checksum is now ${GREEN}ON${RESET}."
    return 0
}

function action_set_auto_checksum_off () {
    check_checksum_off
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} auto checksum"\
            "already is ${RED}OFF${RESET}."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_auto_checksum 'off'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} auto checksum"\
            "to ${RED}OFF${RESET}."
        return 3
    fi
    ok_msg "Auto checksum is now ${RED}OFF${RESET}."
    return 0
}

function action_set_file_editor () {
    echo; info_msg "Type file editor name or ${MAGENTA}.back${RESET}."
    while :
    do
        FILE_EDITOR=`fetch_data_from_user "FileEditor"`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            echo; return 1
        fi
        set_file_editor "$FILE_EDITOR"
        if [ $? -ne 0 ]; then
            warning_msg "Something went wrong."\
                "Could not set default file editor"\
                "${RED}$FILE_EDITOR${RESET}."
            echo; continue
        fi
        break
    done
    ok_msg "Successfully set ${GREEN}$FILE_EDITOR${RESET}"\
        "as the default file editor."
    return 0
}

function action_set_logging_on () {
    check_logging_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} logging"\
            "already is ${GREEN}ON${RESET}."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_foxface_logging 'on'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} logging"\
            "to ${GREEN}ON${RESET}."
        return 3
    fi
    ok_msg "Logging is now ${GREEN}ON${RESET}."
    return 0
}

function action_set_logging_off () {
    check_logging_off
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} logging"\
            "already is ${RED}OFF${RESET}."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_foxface_logging 'off'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} logging"\
            "to ${RED}OFF${RESET}."
        return 3
    fi
    ok_msg "Logging is now ${RED}OFF${RESET}."
    return 0
}

function action_set_safety_off () {
    check_safety_off
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} safety"\
            "already is ${RED}OFF${RESET}."
        return 2
    fi
    echo; qa_msg "Taking off the training wheels. Are you sure about this?"
    fetch_ultimatum_from_user "${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_foxface_safety 'off'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} safety"\
            "to ${RED}OFF${RESET}."
        return 3
    fi
    echo; ok_msg "Safety is now ${RED}OFF${RESET}."
    return 0
}

function action_set_safety_on () {
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "${RED}$SCRIPT_NAME${RESET} safety"\
            "already is ${GREEN}ON${RESET}."
        return 2
    fi
    echo; qa_msg "Getting scared, are we?"
    fetch_ultimatum_from_user "${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        return 1
    fi
    set_foxface_safety 'on'
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$SCRIPT_NAME${RESET} safety"\
            "to ${GREEN}ON${RESET}."
        return 3
    fi
    echo; ok_msg "Safety is now ${GREEN}ON${RESET}."
    return 0
}

# HANDLERS

function handle_directory_decryption_behaviour_pattern_mirror () {
    local DIR_PATH="$1"
    local OPTIONAL="$2"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CLEARTEXT_DIR_NAME=`format_decrypted_file_name "$DIR_NAME"`
    local CLEARTEXT_DIR="$PARENT_DIRECTORY/$CLEARTEXT_DIR_NAME"
    debug_msg "$DIR_PATH - $PARENT_DIRECTORY - $DIR_NAME -"\
        "$CLEARTEXT_DIR_NAME - $CLEARTEXT_DIR"

    check_directory_exists "$CLEARTEXT_DIR"
    if [ $? -eq 0 ]; then
        echo; warning_msg "Output directory ${RED}$CLEARTEXT_DIR${RESET}"\
            "already exists."
        info_msg "Aborting action."
        return 1
    fi

    clone_directory_structure "$DIR_PATH" "$CLEARTEXT_DIR"
    DIRECTORY_FILE_PATHS=( `fetch_all_directory_files "$DIR_PATH"` )
    debug_msg "Files found in directory ($DIR_PATH): ${DIRECTORY_FILE_PATHS[@]}"
    if [ ${#DIRECTORY_FILE_PATHS[@]} -eq 0 ]; then
        warning_msg "No files found in specified directory"\
            "${RED}$DIR_PATH${RESET}."
        info_msg "Rolling back file system to initial state."
        remove_directory "$CLEARTEXT_DIR"
        return 2
    fi

    for file_path in "${DIRECTORY_FILE_PATHS[@]}"; do
        FILE_NAME=`fetch_file_name_from_path "$file_path"`
        local CLEARTEXT_FILE="$CLEARTEXT_DIR/$FILE_NAME.foxn"
        echo; decrypt_aes_256_cbc "$file_path" "$CLEARTEXT_FILE"
        EXIT_CODE=$?
        if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CLEARTEXT_FILE" ]; then
            warning_msg "Something went wrong."\
                "Could not decrypt ${RED}$file_path${RESET} using"\
                "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."
            info_msg "Rolling back file system to initial state."
            remove_directory "$CLEARTEXT_DIR"
            return $EXIT_CODE
        fi
    done

    check_directory_exists "$CLEARTEXT_DIR"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not decrypt target directory"\
            "${YELLOW}$DIR_PATH${RESET}"\
            "to ${RED}$CLEARTEXT_DIR${RESET}."
        return 3
    fi

    echo; ok_msg "Successfully decrypted ${YELLOW}$DIR_PATH${RESET}"\
        "to ${GREEN}$CLEARTEXT_DIR${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."

    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_directory_checksum "$CLEARTEXT_DIR"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_directory_decryption_behaviour_pattern_archive_mirror () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CLEARTEXT_DIR_NAME=`format_decrypted_file_name "$DIR_NAME"`
    UNIVERSAL_DIR_NAME=`format_universal_file_name "$DIR_NAME"`
    local CLEARTEXT_DIR="$PARENT_DIRECTORY/$CLEARTEXT_DIR_NAME"
    local UNIVERSAL_DIR="$PARENT_DIRECTORY/$UNIVERSAL_DIR_NAME"
    handle_directory_decryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    mkdir "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not create directory ${RED}$UNIVERSAL_DIR${RESET}."
        return 1
    fi
    mv "$CLEARTEXT_DIR" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not move cleartext directory "\
            "${RED}$CLEARTEXT_DIR${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi
    cp -r "$DIR_PATH" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not copy ciphertext directory "\
            "${RED}$DIR_PATH${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi
    archive_file "$UNIVERSAL_DIR" "$CLEARTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not archive directory ${RED}$UNIVERSAL_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$UNIVERSAL_DIR${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_directory "$UNIVERSAL_DIR"
    return $EXIT_CODE
}

function handle_directory_encryption_behaviour_pattern_mirror () {
    local DIR_PATH="$1"
    local OPTIONAL="$2"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CIPHERTEXT_DIR_NAME=`format_encrypted_file_name "$DIR_NAME"`
    local CIPHERTEXT_DIR="$PARENT_DIRECTORY/$CIPHERTEXT_DIR_NAME"
    debug_msg "$DIR_PATH - $PARENT_DIRECTORY - $DIR_NAME -"\
        "$CIPHERTEXT_DIR_NAME - $CIPHERTEXT_DIR"

    check_directory_exists "$CIPHERTEXT_DIR"
    if [ $? -eq 0 ]; then
        echo; warning_msg "Output directory ${RED}$CIPHERTEXT_DIR${RESET}"\
            "already exists."
        info_msg "Aborting action."
        return 1
    fi

    clone_directory_structure "$DIR_PATH" "$CIPHERTEXT_DIR"
    DIRECTORY_FILE_PATHS=( `fetch_all_directory_files "$DIR_PATH"` )
    debug_msg "Files found in directory ($DIR_PATH): ${DIRECTORY_FILE_PATHS[@]}"
    if [ ${#DIRECTORY_FILE_PATHS[@]} -eq 0 ]; then
        echo; warning_msg "No files found in specified directory"\
            "${RED}$DIR_PATH${RESET}."
        info_msg "Rolling back file system to initial state."
        remove_directory "$CIPHERTEXT_DIR"
        return 2
    fi

    for file_path in "${DIRECTORY_FILE_PATHS[@]}"; do
        debug_msg "Loading file ($file_path) for encryption."
        FILE_NAME=`fetch_file_name_from_path "$file_path"`
        local CIPHERTEXT_FILE="$CIPHERTEXT_DIR/$FILE_NAME.foxy"

        echo; encrypt_aes_256_cbc "$file_path" "$CIPHERTEXT_FILE"
        EXIT_CODE=$?
        if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CIPHERTEXT_FILE" ]; then
            echo; warning_msg "Something went wrong."\
                "Could not encrypt ${RED}$file_path${RESET} using"\
                "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."
            info_msg "Rolling back file system to initial state."
            remove_directory "$CIPHERTEXT_DIR"
            return $EXIT_CODE
        fi
    done

    check_directory_exists "$CIPHERTEXT_DIR"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not encrypt target directory"\
            "${YELLOW}$DIR_PATH${RESET}"\
            "to ${RED}$CIPHERTEXT_DIR${RESET}."
        return 3
    fi

    echo; ok_msg "Successfully encrypted ${YELLOW}$DIR_PATH${RESET}"\
        "to ${GREEN}$CIPHERTEXT_DIR${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."

    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_directory_checksum "$CIPHERTEXT_DIR"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_action_unmount_encrypted_block_device () {
    echo; while :
    do
        info_msg "Type mapped device path or ${MAGENTA}.back${RESET}."
        display_mapped_devices; echo
        MAPPED_DEVICE_PATH=`fetch_data_from_user "DevPath"`
        EXIT_CODE=$?
        debug_msg "Mapped device path fetched from user ($MAPPED_DEVICE_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            return 1
        fi
        check_valid_mapped_block_device "$MAPPED_DEVICE_PATH"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid mapped device"\
                "${RED}$MAPPED_DEVICE_PATH${RESET}."
            continue
        fi; break
    done
    debug_msg "Mapped device path $MAPPED_DEVICE_PATH"\
        "passed validity check."
    action_unmount_encrypted_block_device "$MAPPED_DEVICE_PATH"
    return $?
}

function handle_action_decrypt_block_device () {
    echo; info_msg "Type block device partition or ${MAGENTA}.back${RESET}."
    display_block_device_partitions
    while :
    do
        DEVICE_PARTITION=`fetch_data_from_user "Partition"`
        if [ $? -ne 0 ]; then
            return 1
        fi
        check_valid_block_device_partition "$DEVICE_PARTITION"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid device partition"\
                "${RED}$DEVICE_PARTITION${RESET}."
            continue
        fi
        break
    done
    action_decrypt_block_device "$DEVICE_PARTITION"
    return $?
}

function handle_action_encrypt_block_device () {
    echo; info_msg "Type device path or ${MAGENTA}.back${RESET}."
    display_block_devices
    while :
    do
        DEVICE_PATH=`fetch_data_from_user "DevicePath"`
        if [ $? -ne 0 ]; then
            return 1
        fi
        check_valid_block_device "$DEVICE_PATH"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid device path ${RED}$DEVICE_PATH${RESET}."
            continue
        fi
        break
    done
    action_encrypt_block_device "$DEVICE_PATH"
    return $?
}

function handle_ciphertext_decryption_behaviour_pattern_archive_mirror () {
    local CIPHERTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxn"
    PARENT_DIRECTORY=`pwd`
    local CLEARTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_ciphertext_decryption_behaviour_pattern_mirror "$CIPHERTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_FILE" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        CLEARTEXT=`cat "$CLEARTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CLEARTEXT_FILE"
    return $EXIT_CODE
}

function handle_file_decryption_behaviour_pattern_archive_mirror () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    UNIVERSAL_DIR_NAME=`format_universal_file_name "$CLEARTEXT_FILE_NAME"`
    local CLEARTEXT_FILE="$FILE_PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"
    local UNIVERSAL_DIR="$FILE_PARENT_DIRECTORY/$UNIVERSAL_DIR_NAME"
    handle_file_decryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    mkdir "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not create directory ${RED}$UNIVERSAL_DIR${RESET}."
        return 1
    fi

    mv "$CLEARTEXT_FILE" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not move cleartext file "\
            "${RED}$CLEARTEXT_FILE${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi

    cp "$FILE_PATH" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not copy ciphertext file "\
            "${RED}$FILE_PATH${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi

    archive_file "$UNIVERSAL_DIR" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive directory ${RED}$UNIVERSAL_DIR${RESET}."
    else
        ok_msg "Successfully archived"\
            "directory ${GREEN}$UNIVERSAL_DIR${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_directory "$UNIVERSAL_DIR"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully shredded"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi
    return $EXIT_CODE
}

function handle_file_decryption_behaviour_pattern_archive_replace () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    local CLEARTEXT_FILE="$FILE_PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"
    handle_file_decryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_FILE" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$CLEARTEXT_FILE"
    remove_file "$FILE_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred ciphertext file ${RED}$FILE_PATH${RESET}."
    else
        ok_msg "Successfully shredded"\
            "ciphertext file ${GREEN}$FILE_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_directory_decryption_behaviour_pattern_archive_replace () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CLEARTEXT_DIR_NAME=`format_decrypted_file_name "$DIR_NAME"`
    local CLEARTEXT_DIR="$PARENT_DIRECTORY/$CLEARTEXT_DIR_NAME"
    handle_directory_decryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_DIR" "$CLEARTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not achive directory ${RED}$CLEARTEXT_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$CLEARTEXT_DIR${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_directory "$CLEARTEXT_DIR"
    remove_directory "$DIR_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not shred directory ${RED}$DIR_PATH${RESET}."
    else
        ok_msg "Successfully shredded directory ${GREEN}$DIR_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_ciphertext_decryption_behaviour_pattern_archive_replace () {
    local CIPHERTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxn"
    PARENT_DIRECTORY=`pwd`
    local CLEARTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_ciphertext_decryption_behaviour_pattern_mirror "$CIPHERTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_FILE" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        CLEARTEXT=`cat "$CLEARTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$CLEARTEXT_FILE"
    return $EXIT_CODE
}

function handle_ciphertext_decryption_behaviour_pattern_archive () {
    local CIPHERTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxn"
    PARENT_DIRECTORY=`pwd`
    local CLEARTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_ciphertext_decryption_behaviour_pattern_mirror "$CIPHERTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_FILE" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not archive cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        CLEARTEXT=`cat "$CLEARTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$CLEARTEXT_FILE"
    return $EXIT_CODE
}

function handle_directory_decryption_behaviour_pattern_archive () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CLEARTEXT_DIR_NAME=`format_decrypted_file_name "$DIR_NAME"`
    local CLEARTEXT_DIR="$PARENT_DIRECTORY/$CLEARTEXT_DIR_NAME"
    handle_directory_decryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_DIR" "$CLEARTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not achive directory ${RED}$CLEARTEXT_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$CLEARTEXT_DIR${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_directory "$CLEARTEXT_DIR"
    return $EXIT_CODE
}

function handle_file_decryption_behaviour_pattern_archive () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    local CLEARTEXT_FILE="$FILE_PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"
    handle_file_decryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CLEARTEXT_FILE" "$CLEARTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive cleartext file ${RED}$CLEARTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "cleartext file ${GREEN}$CLEARTEXT_FILE${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$CLEARTEXT_FILE"
    return $EXIT_CODE
}

function handle_ciphertext_decryption_behaviour_pattern_replace () {
    local CIPHERTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxn"
    PARENT_DIRECTORY=`pwd`
    local CLEARTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_ciphertext_decryption_behaviour_pattern_mirror "$CIPHERTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        CLEARTEXT=`cat "$CLEARTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$CLEARTEXT_FILE"
    return $EXIT_CODE
}

function handle_directory_decryption_behaviour_pattern_replace () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CLEARTEXT_DIR_NAME=`format_decrypted_file_name "$DIR_NAME"`
    local CLEARTEXT_DIR="$PARENT_DIRECTORY/$CLEARTEXT_DIR_NAME"
    handle_directory_decryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT_DIR"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_directory "$DIR_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred directory ${RED}$DIR_PATH${RESET}."
    else
        ok_msg "Successfully shredded directory ${GREEN}$DIR_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_file_decryption_behaviour_pattern_replace () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    local CLEARTEXT_FILE="$FILE_PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"
    handle_file_decryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_data_checksum "$CLEARTEXT_FILE"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_file "$FILE_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred ciphertext file ${RED}$FILE_PATH${RESET}."
    else
        ok_msg "Successfully shredded ciphertext file ${GREEN}$FILE_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_ciphertext_decryption_behaviour_pattern_mirror () {
    local CIPHERTEXT="$1"
    local OPTIONAL="$2"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR"
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    PARENT_DIRECTORY=`pwd`
    local CLEARTEXT_FILE="$PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"

    check_file_exists "$CLEARTEXT_FILE"
    if [ $? -eq 0 ]; then
        debug_msg "File ${RED}$CLEARTEXT_FILE${RESET} already exists."
        COUNT=1
        while :
        do
            local NEW_CLEARTEXT_FILE_NAME="($COUNT)$CLEARTEXT_FILE_NAME"
            debug_msg "Trying ${YELLOW}$NEW_CLEARTEXT_FILE_NAME${RESET}"
            if [ -f "$NEW_CLEARTEXT_FILE_NAME" ]; then
                COUNT=$((COUNT + 1)); continue
            fi
            local CLEARTEXT_FILE="$NEW_CIPHERTEXT_FILE_NAME"; break
        done
    fi

    echo; write_to_file 'override' "${DEFAULT['tmp-file']}" "$CIPHERTEXT"
    echo; decrypt_aes_256_cbc "${DEFAULT['tmp-file']}" "$CLEARTEXT_FILE"
    EXIT_CODE=$?; echo -n > "${DEFAULT['tmp-file']}"

    if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CLEARTEXT_FILE" ]; then
        echo; warning_msg "Something went wrong."\
            "Could not decrypt given data using"\
            "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."
            info_msg "Rolling back file system to initial state."
            remove_file "$CLEARTEXT_FILE"
        return $EXIT_CODE
    fi

    echo; info_msg "Decoded cleartext block:"
    echo; display_file_content "$CLEARTEXT_FILE"

    echo; ok_msg "Successfully decrypted given data"\
        "to ${GREEN}$CLEARTEXT_FILE${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."

    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_FILE"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_file_decryption_behaviour_pattern_mirror () {
    local FILE_PATH="$1"
    local OPTIONAL="$2"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CLEARTEXT_FILE_NAME=`format_decrypted_file_name "$FILE_NAME"`
    local CLEARTEXT_FILE="$FILE_PARENT_DIRECTORY/$CLEARTEXT_FILE_NAME"
    echo; decrypt_aes_256_cbc "$FILE_PATH" "$CLEARTEXT_FILE"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CLEARTEXT_FILE" ]; then
        echo; warning_msg "Something went wrong."\
            "Could not decrypt ${RED}$FILE_PATH${RESET} using"\
            "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."
        info_msg "Rolling back file system to initial state."
        remove_file "$CLEARTEXT_FILE"
        return $EXIT_CODE
    fi
    echo; ok_msg "Successfully decrypted ${YELLOW}$FILE_PATH${RESET}"\
        "to ${GREEN}$CLEARTEXT_FILE${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($DECRYPTION_BEHAVIOUR)."
    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_file_checksum "$CLEARTEXT_FILE"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_file_encryption_behaviour_pattern_archive_mirror () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CIPHERTEXT_FILE_NAME=`format_encrypted_file_name "$FILE_NAME"`
    UNIVERSAL_DIR_NAME=`format_universal_file_name "$CIPHERTEXT_FILE_NAME"`
    local CIPHERTEXT_FILE="$FILE_PARENT_DIRECTORY/$CIPHERTEXT_FILE_NAME"
    local UNIVERSAL_DIR="$FILE_PARENT_DIRECTORY/$UNIVERSAL_DIR_NAME"
    handle_file_encryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    mkdir "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not create directory ${RED}$UNIVERSAL_DIR${RESET}."
        info_msg "Rolling back file system to initial state."
        remove_file "$CIPHERTEXT_FILE"
        return 1
    fi

    mv "$CIPHERTEXT_FILE" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not move ciphertext file "\
            "${RED}$CIPHERTEXT_FILE${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi

    cp "$FILE_PATH" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not copy cleartext file "\
            "${RED}$FILE_PATH${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi

    archive_file "$UNIVERSAL_DIR" "$CIPHERTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive directory ${RED}$UNIVERSAL_DIR${RESET}."
    else
        ok_msg "Successfully archived"\
            "directory ${GREEN}$UNIVERSAL_DIR${RESET}."
    fi

    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi

    remove_directory "$UNIVERSAL_DIR"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred directory ${RED}$CIPHERTEXT_FILE${RESET}."
    else
        ok_msg "Successfully shredded"\
            "directory ${GREEN}$CIPHERTEXT_FILE${RESET}."
    fi
    return $EXIT_CODE
}

function handle_directory_encryption_behaviour_pattern_archive_mirror () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CIPHERTEXT_DIR_NAME=`format_encrypted_file_name "$DIR_NAME"`
    UNIVERSAL_DIR_NAME=`format_universal_file_name "$DIR_NAME"`
    local CIPHERTEXT_DIR="$PARENT_DIRECTORY/$CIPHERTEXT_DIR_NAME"
    local UNIVERSAL_DIR="$PARENT_DIRECTORY/$UNIVERSAL_DIR_NAME"
    handle_directory_encryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    mkdir "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        error_msg "Something went wrong."\
            "Could not create directory ${RED}$UNIVERSAL_DIR${RESET}."
        info_msg "Rolling back file system to initial state."
        remove_directory "$CIPHERTEXT_DIR"
        return 1
    fi
    mv "$CIPHERTEXT_DIR" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not move ciphertext directory "\
            "${RED}$CIPHERTEXT_DIR${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi
    cp -r "$DIR_PATH" "$UNIVERSAL_DIR" &> /dev/null
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not copy cleartext directory "\
            "${RED}$DIR_PATH${RESET} to ${YELLOW}$UNIVERSAL_DIR${RESET}."
    fi
    archive_file "$UNIVERSAL_DIR" "$CIPHERTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not archive directory ${RED}$UNIVERSAL_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$UNIVERSAL_DIR${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_directory "$UNIVERSAL_DIR"
    return $EXIT_CODE
}

function handle_cleartext_encryption_behaviour_pattern_archive_mirror () {
    local CLEARTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxy"
    PARENT_DIRECTORY=`pwd`
    local CIPHERTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_cleartext_encryption_behaviour_pattern_mirror "$CLEARTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_FILE" "$CIPHERTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive ciphertext file ${RED}$CIPHERTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "ciphertext file ${GREEN}$CIPHERTEXT_FILE${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        CIPHERTEXT=`cat "$CIPHERTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CIPHERTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CIPHERTEXT_FILE"
    return $EXIT_CODE
}

function handle_file_encryption_behaviour_pattern_archive_replace () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CIPHERTEXT_FILE_NAME=`format_encrypted_file_name "$FILE_NAME"`
    local CIPHERTEXT_FILE="$FILE_PARENT_DIRECTORY/$CIPHERTEXT_FILE_NAME"
    handle_file_encryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_FILE" "$CIPHERTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive ciphertext file ${RED}$CIPHERTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "ciphertext file ${GREEN}$CIPHERTEXT_FILE${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CIPHERTEXT_FILE"
    remove_file "$FILE_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not shred cleartext file ${RED}$FILE_PATH${RESET}."
    else
        ok_msg "Successfully shredded"\
            "cleartext file ${GREEN}$FILE_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_directory_encryption_behaviour_pattern_archive_replace () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CIPHERTEXT_DIR_NAME=`format_encrypted_file_name "$DIR_NAME"`
    local CIPHERTEXT_DIR="$PARENT_DIRECTORY/$CIPHERTEXT_DIR_NAME"
    handle_directory_encryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_DIR" "$CIPHERTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not achive directory ${RED}$CIPHERTEXT_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$CIPHERTEXT_DIR${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_directory "$CIPHERTEXT_DIR"
    remove_directory "$DIR_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not shred directory ${RED}$DIR_PATH${RESET}."
    else
        ok_msg "Successfully shredded directory ${GREEN}$DIR_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_cleartext_encryption_behaviour_pattern_archive_replace () {
    local CLEARTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxy"
    PARENT_DIRECTORY=`pwd`
    local CIPHERTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_cleartext_encryption_behaviour_pattern_mirror "$CLEARTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        CIPHERTEXT=`cat "$CIPHERTEXT_FILE"`
        FILE_CHECKSUM=`create_data_checksum "$CIPHERTEXT"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CIPHERTEXT_FILE"
    return $EXIT_CODE
}

function handle_file_encryption_behaviour_pattern_archive () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CIPHERTEXT_FILE_NAME=`format_encrypted_file_name "$FILE_NAME"`
    local CIPHERTEXT_FILE="$FILE_PARENT_DIRECTORY/$CIPHERTEXT_FILE_NAME"
    handle_file_encryption_behaviour_pattern_mirror "$FILE_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_FILE" "$CIPHERTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not archive ciphertext file ${RED}$CIPHERTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "ciphertext file ${GREEN}$CIPHERTEXT_FILE${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CIPHERTEXT_FILE"
    return $EXIT_CODE
}

function handle_directory_encryption_behaviour_pattern_archive () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CIPHERTEXT_DIR_NAME=`format_encrypted_file_name "$DIR_NAME"`
    local CIPHERTEXT_DIR="$PARENT_DIRECTORY/$CIPHERTEXT_DIR_NAME"
    handle_directory_encryption_behaviour_pattern_mirror "$DIR_PATH" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_DIR" "$CIPHERTEXT_DIR.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not achive directory ${RED}$CIPHERTEXT_DIR${RESET}."
    else
        ok_msg "Successfully archived directory ${GREEN}$CIPHERTEXT_DIR${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_DIR.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_directory "$CIPHERTEXT_DIR"
    return $EXIT_CODE
}

function handle_cleartext_encryption_behaviour_pattern_archive () {
    local CLEARTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxy"
    PARENT_DIRECTORY=`pwd`
    local CIPHERTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_cleartext_encryption_behaviour_pattern_mirror "$CLEARTEXT" 'no-checksum'
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    archive_file "$CIPHERTEXT_FILE" "$CIPHERTEXT_FILE.tar"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not archive ciphertext file ${RED}$CIPHERTEXT_FILE${RESET}."
    else
        ok_msg "Successfully archived"\
            "ciphertext file ${GREEN}$CIPHERTEXT_FILE${RESET}."
    fi
    check_checksum_on
    if [ $? -eq 0 ]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE.tar"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    remove_file "$CIPHERTEXT_FILE"
    return $EXIT_CODE
}

function handle_file_encryption_behaviour_pattern_replace () {
    local FILE_PATH="$1"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CIPHERTEXT_FILE_NAME=`format_encrypted_file_name "$FILE_NAME"`
    local CIPHERTEXT_FILE="$FILE_PARENT_DIRECTORY/$CIPHERTEXT_FILE_NAME"
    handle_file_encryption_behaviour_pattern_mirror "$FILE_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    remove_file "$FILE_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not shred cleartext file ${RED}$FILE_PATH${RESET}."
    else
        ok_msg "Successfully shredded cleartext file ${GREEN}$FILE_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_directory_encryption_behaviour_pattern_replace () {
    local DIR_PATH="$1"
    PARENT_DIRECTORY=`fetch_directory_from_file_path "$DIR_PATH"`
    DIR_NAME=`fetch_file_name_from_path "$DIR_PATH"`
    CIPHERTEXT_DIR_NAME=`format_encrypted_file_name "$DIR_NAME"`
    local CIPHERTEXT_DIR="$PARENT_DIRECTORY/$CIPHERTEXT_DIR_NAME"
    handle_directory_encryption_behaviour_pattern_mirror "$DIR_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    remove_directory "$DIR_PATH"
    if [ $? -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Cold not shred directory ${RED}$DIR_PATH${RESET}."
    else
        ok_msg "Successfully shredded directory ${GREEN}$DIR_PATH${RESET}."
    fi
    return $EXIT_CODE
}

function handle_cleartext_encryption_behaviour_pattern_replace () {
    local CLEARTEXT="$@"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxy"
    PARENT_DIRECTORY=`pwd`
    local CIPHERTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"
    handle_cleartext_encryption_behaviour_pattern_mirror "$CLEARTEXT"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        return $EXIT_CODE
    fi
    remove_file "$CIPHERTEXT_FILE"
    return $EXIT_CODE
}

function handle_cleartext_encryption_behaviour_pattern_mirror () {
    local CLEARTEXT="$1"
    local OPTIONAL="$2"
    local FILE_NAME="$FOXFACE_ENCRYPTION-$ENCRYPTION_BEHAVIOUR.foxy"
    PARENT_DIRECTORY=`pwd`
    local CIPHERTEXT_FILE="$PARENT_DIRECTORY/$FILE_NAME"

    check_file_exists "$CIPHERTEXT_FILE"
    if [ $? -eq 0 ]; then
        debug_msg "File ${RED}$CIPHERTEXT_FILE${RESET} already exists."
        COUNT=1; while :
        do
            local NEW_CIPHERTEXT_FILE_NAME="($COUNT)$FILE_NAME"
            debug_msg "Trying ${YELLOW}$NEW_CIPHERTEXT_FILE_NAME${RESET}"
            if [ -f $NEW_CIPHERTEXT_FILE_NAME ]; then
                COUNT=$((COUNT + 1)); continue
            fi
            local CIPHERTEXT_FILE=$NEW_CIPHERTEXT_FILE_NAME; break
        done
    fi

    echo; write_to_file 'override' "${DEFAULT['tmp-file']}" "$CLEARTEXT"
    echo; encrypt_aes_256_cbc "${DEFAULT['tmp-file']}" "$CIPHERTEXT_FILE"
    EXIT_CODE=$?; echo -n > "${DEFAULT['tmp-file']}"

    if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CIPHERTEXT_FILE" ]; then
        echo; warning_msg "Something went wrong."\
            "Could not encrypt given data using"\
            "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."
        info_msg "Rolling back file system to initial state."
        remove_file "$CIPHERTEXT_FILE"
        return $EXIT_CODE
    fi

    echo; info_msg "Encoded ciphertext block:"
    echo; display_file_content "$CIPHERTEXT_FILE"

    echo; ok_msg "Successfully encrypted given data"\
        "to ${GREEN}$CIPHERTEXT_FILE${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."

    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_file_encryption_behaviour_pattern_mirror () {
    local FILE_PATH="$1"
    local OPTIONAL="$2"
    FILE_PARENT_DIRECTORY=`fetch_directory_from_file_path "$FILE_PATH"`
    FILE_NAME=`fetch_file_name_from_path "$FILE_PATH"`
    CIPHERTEXT_FILE_NAME=`format_encrypted_file_name "$FILE_NAME"`
    local CIPHERTEXT_FILE="$FILE_PARENT_DIRECTORY/$CIPHERTEXT_FILE_NAME"
    echo; encrypt_aes_256_cbc "$FILE_PATH" "$CIPHERTEXT_FILE"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ] || [ ! -f "$CIPHERTEXT_FILE" ]; then
        echo; warning_msg "Something went wrong."\
            "Could not encrypt ${RED}$FILE_PATH${RESET} using"\
            "${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."
        info_msg "Rolling back file system to initial state."
        remove_file "$CIPHERTEXT_FILE"
        return $EXIT_CODE
    fi
    echo; ok_msg "Successfully encrypted ${YELLOW}$FILE_PATH${RESET}"\
        "to ${GREEN}$CIPHERTEXT_FILE${RESET}"\
        "using ${CYAN}$FOXFACE_ENCRYPTION${RESET} ($ENCRYPTION_BEHAVIOUR)."
    check_checksum_on
    if [ $? -eq 0 ] && [[ "$OPTIONAL" != 'no-checksum' ]]; then
        FILE_CHECKSUM=`create_file_checksum "$CIPHERTEXT_FILE"`
        symbol_msg "${BLUE}$FOXFACE_CHECKSUM${RESET}" \
            "$FILE_CHECKSUM"
    fi
    return $EXIT_CODE
}

function handle_action_decrypt_file () {
    while :
    do
        echo; info_msg "Type absolute file path or ${MAGENTA}.back${RESET}."
        FILE_PATH=`fetch_data_from_user "FilePath"`
        EXIT_CODE=$?; debug_msg "File path fetched from user ($FILE_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_file_exists "$FILE_PATH"
        EXIT_CODE=$?
        debug_msg "File path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "File path required, not"\
                "${RED}$FILE_PATH${RESET}."
            continue
        fi; break
    done
    action_decrypt_file "$FILE_PATH"
    return $?
}

function handle_action_decrypt_directory () {
    while :
    do
        echo; info_msg "Type absolute directory path or ${MAGENTA}.back${RESET}."
        DIR_PATH=`fetch_data_from_user "DirPath"`
        EXIT_CODE=$?; debug_msg "Directory path fetched from user ($DIR_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_directory_exists "$DIR_PATH"
        EXIT_CODE=$?
        debug_msg "Directory path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "Directory path required, not"\
                "${RED}$DIR_PATH${RESET}."
            continue
        fi; break
    done
    action_decrypt_directory "$DIR_PATH"
    return $?
}

function handle_action_encrypt_string () {
    while :
    do
        INFO_MSG=`info_msg "Opening ${MAGENTA}${DEFAULT['file-editor']}${RESET}"\
            "for data gathering"`
        echo; echo -n $INFO_MSG; three_second_delay

        echo -n > ${DEFAULT['tmp-file']}
        ${DEFAULT['file-editor']} ${DEFAULT['tmp-file']}
        CLEARTEXT="`cat ${DEFAULT['tmp-file']}`"
        echo -n > ${DEFAULT['tmp-file']}

        debug_msg "Cleartext fetched from user ($CLEARTEXT)."
        break
    done
    action_encrypt_string "$CLEARTEXT"
    return $?
}

function handle_action_decrypt_string () {
    while :
    do
        INFO_MSG=`info_msg "Opening ${MAGENTA}${DEFAULT['file-editor']}${RESET}"\
            "for data gathering"`
        echo; echo -n $INFO_MSG; three_second_delay

        echo -n > ${DEFAULT['tmp-file']}
        ${DEFAULT['file-editor']} ${DEFAULT['tmp-file']}
        CIPHERTEXT="`cat ${DEFAULT['tmp-file']}`"
        echo -n > ${DEFAULT['tmp-file']}

        debug_msg "Ciphertext fetched from user ($CIPHERTEXT)."
        break
    done
    action_decrypt_string "$CIPHERTEXT"
    return $?
}

function handle_action_encrypt_directory () {
    while :
    do
        echo; info_msg "Type absolute directory path or ${MAGENTA}.back${RESET}."
        DIR_PATH=`fetch_data_from_user "DirPath"`
        EXIT_CODE=$?; debug_msg "Directory path fetched from user ($DIR_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_directory_exists "$DIR_PATH"
        EXIT_CODE=$?
        debug_msg "Directory path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "Directory path required, not"\
                "${RED}$DIR_PATH${RESET}."
            continue
        fi; break
    done
    action_encrypt_directory "$DIR_PATH"
    return $?
}

function handle_decryption_behaviour_pattern_archive_mirror () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_decryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_decryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        'ciphertext')
            handle_ciphertext_decryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_decryption_behaviour_pattern_archive () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_decryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_decryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        'ciphertext')
            handle_ciphertext_decryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_decryption_behaviour_pattern_archive_replace () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_decryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_decryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        'ciphertext')
            handle_ciphertext_decryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_decryption_behaviour_pattern_mirror () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_decryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_decryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        'ciphertext')
            handle_ciphertext_decryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_decryption_behaviour_pattern_replace () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_decryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_decryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        'ciphertext')
            handle_ciphertext_decryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_encryption_behaviour_pattern_archive_replace () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_encryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_encryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        'cleartext')
            handle_cleartext_encryption_behaviour_pattern_archive_replace "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_encryption_behaviour_pattern_archive_mirror () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_encryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_encryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        'cleartext')
            handle_cleartext_encryption_behaviour_pattern_archive_mirror "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_encryption_behaviour_pattern_mirror () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_encryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_encryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        'cleartext')
            handle_cleartext_encryption_behaviour_pattern_mirror "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_encryption_behaviour_pattern_replace () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_encryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_encryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        'cleartext')
            handle_cleartext_encryption_behaviour_pattern_replace "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_encryption_behaviour_pattern_archive () {
    local TARGET_MODE="$1"
    local TARGET_CONTENT="$2"
    case "$TARGET_MODE" in
        'file')
            handle_file_encryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        'directory')
            handle_directory_encryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        'cleartext')
            handle_cleartext_encryption_behaviour_pattern_archive "$TARGET_CONTENT"
            ;;
        *)
            echo; error_msg "Invalid behaviour mode ${RED}$TAGET_MODE${RESET}."
            return 1
            ;;
    esac
    return $?
}

function handle_action_encrypt_file () {
    while :
    do
        echo; info_msg "Type absolute file path or ${MAGENTA}.back${RESET}."
        FILE_PATH=`fetch_data_from_user "FilePath"`
        EXIT_CODE=$?; debug_msg "File path fetched from user ($FILE_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_file_exists "$FILE_PATH"
        EXIT_CODE=$?
        debug_msg "File path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "File path required, not"\
                "${RED}$FILE_PATH${RESET}."
            continue
        fi; break
    done
    action_encrypt_file "$FILE_PATH"
    return $?
}

function handle_action_create_checksum_of_string () {
    INFO_MSG=`info_msg "Opening ${MAGENTA}${DEFAULT['file-editor']}${RESET}"\
        "for data gathering"`
    echo; echo -n $INFO_MSG; three_second_delay
    echo -n > ${DEFAULT['tmp-file']}
    ${DEFAULT['file-editor']} ${DEFAULT['tmp-file']}
    STRING_TO_HASH="`cat ${DEFAULT['tmp-file']}`"
    echo -n > ${DEFAULT['tmp-file']}
    action_create_checksum_of_string "$STRING_TO_HASH"
    return $?
}

function handle_action_create_checksum_of_file () {
    while :
    do
        echo; info_msg "Type absolute file path or ${MAGENTA}.back${RESET}."
        FILE_PATH=`fetch_data_from_user "FilePath"`
        EXIT_CODE=$?; debug_msg "File path fetched from user ($FILE_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_file_exists "$FILE_PATH"
        EXIT_CODE=$?
        debug_msg "File path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "File path required, not"\
                "${RED}$FILE_PATH${RESET}."
            continue
        fi; break
    done
    action_create_checksum_of_file "$FILE_PATH"
    return $?
}

function handle_action_compare_checksum_of_string () {
    while :
    do
        echo; info_msg "Type string checksum or ${MAGENTA}.back${RESET}."
        CHECKSUM=`fetch_data_from_user "Checksum"`
        EXIT_CODE=$?
        debug_msg "Checksum fetched from user ${YELLOW}$CHECKSUM${RESET}."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_valid_checksum "$CHECKSUM"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid $FOXFACE_CHECKSUM checksum"\
                "${RED}$CHECKSUM${RESET}."
            continue
        fi; break
    done
    INFO_MSG=`info_msg "Opening ${MAGENTA}${DEFAULT['file-editor']}${RESET}"\
        "for data gathering"`
    echo; echo -n $INFO_MSG; three_second_delay
    echo -n > ${DEFAULT['tmp-file']}
    ${DEFAULT['file-editor']} ${DEFAULT['tmp-file']}
    STRING_TO_COMPARE="`cat ${DEFAULT['tmp-file']}`"
    action_compare_checksum_of_string "$CHECKSUM" "$STRING_TO_COMPARE"
    EXIT_CODE=$?
    echo -n > ${DEFAULT['tmp-file']}
    return $EXIT_CODE
}

function handle_action_compare_checksum_of_file () {
    while :
    do
        echo; info_msg "Type absolute file path or ${MAGENTA}.back${RESET}."
        FILE_PATH=`fetch_data_from_user "FilePath"`
        EXIT_CODE=$?; debug_msg "File path fetched from user ($FILE_PATH)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        CHECK_VALID=`check_file_exists "$FILE_PATH"`
        EXIT_CODE=$?
        debug_msg "File path validity check exit code ($EXIT_CODE)."
        if [ $EXIT_CODE -ne 0 ]; then
            echo; warning_msg "File path required, not"\
                "${RED}$FILE_PATH${RESET}."
            continue
        fi; break
    done
    while :
    do
        echo; info_msg "Type ${YELLOW}$FILE_PATH${RESET}"\
            "${CYAN}$FOXFACE_CHECKSUM${RESET} checksum"\
            "or ${MAGENTA}.back${RESET}."
        CHECKSUM=`fetch_data_from_user "Checksum"`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        CHECK_VALID=`check_valid_checksum "$CHECKSUM"`
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid $FOXFACE_CHECKSUM checksum"\
                "${RED}$CHECKSUM${RESET}."
            continue
        fi; break
    done
    action_compare_checksum_of_file "$FILE_PATH" "$CHECKSUM"
    return $?
}

# CONTROLLERS

function foxface_unmount_encrypted_block_device_controller () {
    OPTIONS=(
        'Unmount Mapped Device'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Breaking Orbit${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Unmount Mapped Device')
                handle_action_unmount_encrypted_block_device; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function foxface_log_viewer_controller () {
    OPTIONS=(
        'Display Log Tail'
        'Display Log Head'
        'Display More'
        'Clear Log File'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Log Viewer${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Display Log Tail')
                action_log_view_tail; break
                ;;
            'Display Log Head')
                action_log_view_head; break
                ;;
            'Display More')
                action_log_view_more; break
                ;;
            'Clear Log File')
                action_clear_log_file; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function foxface_control_panel () {
    OPTIONS=(
        "Set ${RED}Safety OFF${RESET}"
        "Set ${GREEN}Safety ON${RESET}"
        'Set Encryption Algorithm'
        'Set Hashing Algorithm'
        'Set Encryption Behaviour'
        'Set Decryption Behaviour'
        'Set File Editor'
        'Set Auto Checksum ON'
        'Set Auto Checksum OFF'
        'Set Logging ON'
        'Set Logging OFF'
        'Install Dependencies'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Control Panel${RESET}"
    display_settings
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            "Set ${RED}Safety OFF${RESET}")
                action_set_safety_off; break
                ;;
            "Set ${GREEN}Safety ON${RESET}")
                action_set_safety_on; break
                ;;
            'Set Encryption Algorithm')
                action_set_encryption_algorithm; break
                ;;
            'Set Hashing Algorithm')
                action_set_hashing_algorithm; break
                ;;
            'Set Encryption Behaviour')
                action_set_encryption_behaviour; break
                ;;
            'Set Decryption Behaviour')
                action_set_decryption_behaviour; break
                ;;
            'Set Auto Checksum ON')
                action_set_auto_checksum_on; break
                ;;
            'Set Auto Checksum OFF')
                action_set_auto_checksum_off; break
                ;;
            'Set File Editor')
                action_set_file_editor; break
                ;;
            'Set Logging ON')
                action_set_logging_on; break
                ;;
            'Set Logging OFF')
                action_set_logging_off; break
                ;;
            'Install Dependencies')
                apt_install_foxface_dependencies; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function foxface_checksum_controller () {
    OPTIONS=(
        'Create Checksum of String'
        'Create Checksum of File'
        'Compare Checksum of String'
        'Compare Checksum of File'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Checksum Mix-Of-Kit${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Create Checksum of String')
                handle_action_create_checksum_of_string; break
                ;;
            'Create Checksum of File')
                handle_action_create_checksum_of_file; break
                ;;
            'Compare Checksum of String')
                handle_action_compare_checksum_of_string; break
                ;;
            'Compare Checksum of File')
                handle_action_compare_checksum_of_file; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function foxface_decryption_controller () {
    OPTIONS=(
        'Decrypt File'
        'Decrypt Directory'
        'Decrypt String'
        'Decrypt Block Device'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Decryption Mix-Of-Kit${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Decrypt File')
                handle_action_decrypt_file; break
                ;;
            'Decrypt Directory')
                handle_action_decrypt_directory; break
                ;;
            'Decrypt String')
                handle_action_decrypt_string; break
                ;;
            'Decrypt Block Device')
                handle_action_decrypt_block_device; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function foxface_encryption_controller () {
    OPTIONS=(
        'Encrypt File'
        'Encrypt Directory'
        'Encrypt String'
        'Encrypt Block Device'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Encryption Mix-Of-Kit${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Encrypt File')
                handle_action_encrypt_file; break
                ;;
            'Encrypt Directory')
                handle_action_encrypt_directory; break
                ;;
            'Encrypt String')
                handle_action_encrypt_string; break
                ;;
            'Encrypt Block Device')
                handle_action_encrypt_block_device; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function fox_face_main_controller () {
    OPTIONS=(
        'Fox Encrypt'
        'Fox Decrypt'
        'Fox Checksum'
        'Unmount Encrypted Device'
        'Control Panel'
        "View ${BLUE}$SCRIPT_NAME${RESET} Logs"
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Trade Secret${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Fox Encrypt')
                init_foxface_encryption_controller; break
                ;;
            'Fox Decrypt')
                init_foxface_decryption_controller; break
                ;;
            'Fox Checksum')
                init_foxface_checksum_controller; break
                ;;
            'Unmount Encrypted Device')
                init_foxface_unmount_encrypted_block_device_controller; break
                ;;
            'Control Panel')
                init_foxface_control_panel; break
                ;;
            "View ${BLUE}$SCRIPT_NAME${RESET} Logs")
                init_foxface_log_viewer_controller; break
                ;;
            'Back')
                clear; ok_msg "Terminating ${BLUE}$SCRIPT_NAME${RESET}.
                "
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

# INIT

function init_foxface_unmount_encrypted_block_device_controller () {
    while :
    do
        foxface_unmount_encrypted_block_device_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_log_viewer_controller () {
    while :
    do
        foxface_log_viewer_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_mount_encrypted_block_device_controller () {
    while :
    do
        foxface_mount_encrypted_block_device_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_unmount_encrypted_block_device_controller () {
    while :
    do
        foxface_unmount_encrypted_block_device_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_encryption_controller () {
    while :
    do
        foxface_encryption_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_decryption_controller () {
    while :
    do
        foxface_decryption_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_checksum_controller () {
    while :
    do
        foxface_checksum_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_foxface_control_panel () {
    while :
    do
        foxface_control_panel
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_fox_face_main_controller () {
    while :
    do
        fox_face_main_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

# DISPLAY

function display_mapped_devices () {
    MAPPED_DEVICES=( `fetch_mapped_block_devices_with_encryption` )
    echo; echo "${CYAN}MAPPED BLOCK DEVICES"${RESET}
    for mapped_dev in "${MAPPED_DEVICES[@]}"; do
        echo "${DEFAULT['mapper-dir']}/$mapped_dev"
    done
}

function display_block_device_partitions () {
    echo; echo "${CYAN}PARTITION TABLE${RESET}" && \
        cat "${DEFAULT['partition-file']}" | \
        grep -v 'ram' | \
        grep -e '[0-9]$' | \
        awk '{print $NF}' | \
        sed 's/^/\/dev\//g'
    EXIT_CODE=$?
    echo; return $EXIT_CODE
}

function display_block_devices () {
    echo; echo -n "${CYAN}DEVICE${RESET}" && \
        echo ${CYAN}`lsblk | grep -e MOUNTPOINT`${RESET} && \
        lsblk | grep -e 'disk' | sed 's/^/\/dev\//g'
    EXIT_CODE=$?
    echo; return $EXIT_CODE
}

function display_file_content () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid file path ${RED}$FILE_PATH${RESET}."
        return 1
    fi
    cat "$FILE_PATH"
    return $?
}

function display_settings () {
    DISPLAY_AUTO_CHECKSUM_FLAG=`format_flag_colors "$FOXFACE_AUTO_CHECKSUM"`
    DISPLAY_LOGGING_FLAG=`format_flag_colors "$FOXFACE_LOGGING"`
    DISPLAY_SAFETY_FLAG=`format_flag_colors "$FOXFACE_SAFETY"`
    echo "
[ ${CYAN}Encryption Algorithm${RESET}  ]: ${MAGENTA}$FOXFACE_ENCRYPTION${RESET}
[ ${CYAN}Hashing Algorithm${RESET}     ]: ${MAGENTA}$FOXFACE_CHECKSUM${RESET}
[ ${CYAN}Encryption Behaviour${RESET}  ]: ${MAGENTA}$ENCRYPTION_BEHAVIOUR${RESET}
[ ${CYAN}Decryption Behaviour${RESET}  ]: ${MAGENTA}$DECRYPTION_BEHAVIOUR${RESET}
[ ${CYAN}Temoporary File${RESET}       ]: ${YELLOW}${DEFAULT['tmp-file']}${RESET}
[ ${CYAN}File Editor${RESET}           ]: ${YELLOW}${DEFAULT['file-editor']}${RESET}
[ ${CYAN}Auto Checksum${RESET}         ]: $DISPLAY_AUTO_CHECKSUM_FLAG
[ ${CYAN}Logging${RESET}               ]: $DISPLAY_LOGGING_FLAG
[ ${CYAN}Safety${RESET}                ]: $DISPLAY_SAFETY_FLAG
"
    return 0
}

function display_encryption_behaviour_description () {
    local BEHAVIOUR_LABEL="$1"
    check_valid_encryption_behaviour_label "$BEHAVIOUR_LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid encryption behaviour label"\
            "${RED}$BEHAVIOUR${RESET}."
        return 1
    fi
    BEHAVIOUR_DESCRIPTION=`fetch_encryption_behaviour_description_by_label \
        "$BEHAVIOUR_LABEL"`
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch behaviour ${RED}$BEHAVIOUR_DESCRIPTION${RESET}"\
            "description."
        return 2
    fi
    format_description $BEHAVIOUR_DESCRIPTION
    return $?
}

function display_decryption_behaviour_description () {
    local BEHAVIOUR_LABEL="$1"
    check_valid_decryption_behaviour_label "$BEHAVIOUR_LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid decryption behaviour label"\
            "${RED}$BEHAVIOUR${RESET}."
        return 1
    fi
    BEHAVIOUR_DESCRIPTION=`fetch_decryption_behaviour_description_by_label \
        "$BEHAVIOUR_LABEL"`
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not fetch behaviour ${RED}$BEHAVIOUR_DESCRIPTION${RESET}"\
            "description."
        return 1
    fi
    format_description $BEHAVIOUR_DESCRIPTION
    return $?
}

function display_behaviour_description () {
    local DISPLAY_TARGET="$1"
    local BEHAVIOUR_LABEL="$2"
    if [[ "$DISPLAY_TARGET" != 'encryption' ]] && [[ "$DISPLAY_TARGET" != 'decryption' ]]; then
        echo; error_msg "Invalid behaviour target"\
            "${RED}$DISPLAY_TARGET${RESET}."
        return 1
    fi
    case "$DISPLAY_TARGET" in
        'encryption')
            display_encryption_behaviour_description "$BEHAVIOUR_LABEL"
            ;;
        'decryption')
            display_decryption_behaviour_description "$BEHAVIOUR_LABEL"
            ;;
        *)
            echo; error_msg "Software failure!"
            return 2
            ;;
    esac
    return $?
}

function debug_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    log_message 'SYMBOL' "${MAGENTA}DEBUG${RESET}" "$MSG"
    return 0
}

function done_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${BLUE}DONE${RESET} ]: $MSG"
    log_message 'SYMBOL' "${BLUE}DONE${RESET}" "$MSG"
    return 0
}

function ok_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${GREEN}OK${RESET} ]: $MSG"
    log_message 'SYMBOL' "${GREEN}OK${RESET}" "$MSG"
    return 0
}

function nok_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}NOK${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}NOK${RESET}" "$MSG"
    return 0
}

function qa_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${YELLOW}Q/A${RESET} ]: $MSG"
    log_message 'SYMBOL' "${YELLOW}Q/A${RESET}" "$MSG"
    return 0
}

function info_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${YELLOW}INFO${RESET} ]: $MSG"
    log_message 'SYMBOL' "${YELLOW}INFO${RESET}" "$MSG"
    return 0
}

function error_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}ERROR${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}ERROR${RESET}" "$MSG"
    return 0
}

function warning_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}WARNING${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}WARNING${RESET}" "$MSG"
    return 0
}

function symbol_msg () {
    local SYMBOL="$1"
    local MSG="${@:2}"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ $SYMBOL ]: $MSG"
    log_message 'SYMBOL' "$SYMBOL" "$MSG"
    return 0
}

# MISCELLANEOUS

init_fox_face_main_controller

