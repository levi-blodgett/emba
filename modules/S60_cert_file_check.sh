#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Scrapes firmware for certification files and their end date.

S60_cert_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search certificates"
  pre_module_reporter "${FUNCNAME[0]}"

  local CERT_FILES_ARR=()
  readarray -t CERT_FILES_ARR < <(config_find "$CONFIG_DIR""/cert_files.cfg")

  local CERT_FILE_CNT=0
  local TOTAL_CERT_CNT=0
  local CERT_OUT_CNT=0
  local CERT_WARNING_CNT=0
  local NESTED_CERT_CNT=0
  local ERROR_CODE=0
  local CERT_EXPIRE_WATCH_DATE="2 years"
  local CURRENT_DATE=""
  local FUTURE_DATE=""
  local LINE=""
  local CERT_NAME=""
  local CERT_LOG=""
  local CERT_DATES_ARR=()
  local CERT_DATES_ARR_=()
  local SIGNATURE_LINES_ARR=()

  if [[ "${CERT_FILES_ARR[0]-}" == "C_N_F" ]]; then print_output "[!] Config not found"
  elif [[ ${#CERT_FILES_ARR[@]} -ne 0 ]]; then
    write_csv_log "Certificate file" "Certificate expire on" "Certificate expired"
    print_output "[+] Found ""$ORANGE${#CERT_FILES_ARR[@]}$GREEN"" possible certification files:"
    print_ln
    CURRENT_DATE=$(date +%s)
    FUTURE_DATE=$(date --date="$CERT_EXPIRE_WATCH_DATE" +%s)
    for LINE in "${CERT_FILES_ARR[@]}" ; do
      if [[ -f "$LINE" && $(wc -l "$LINE" | awk '{print $1}'|| true) -gt 1 ]]; then
        ((CERT_FILE_CNT+=1))
        if command -v openssl > /dev/null ; then
          CERT_DATES_ARR=()
          CERT_DATES_ARR_=()
          SIGNATURE_LINES_ARR=()
          NESTED_CERT_CNT=0
          CERT_NAME=$(basename "$LINE")
          CERT_LOG="$LOG_PATH_MODULE/cert_details_$CERT_NAME.txt"
          write_log "[*] Cert file: $LINE\n" "$CERT_LOG"
          while openssl x509 -noout -text 2>/dev/null >> "$CERT_LOG"; do 
            ((TOTAL_CERT_CNT++))
            ((NESTED_CERT_CNT++))
            write_log "" "$CERT_LOG"
            END_DATE_LINE=$(grep 'Not After :' "$CERT_LOG" | awk -v cnt="$NESTED_CERT_CNT" 'NR==cnt')
            END_DATE=${END_DATE_LINE#*:}
            CERT_DATE=$(date --date="$END_DATE" --iso-8601 || true)
            CERT_DATE_=$(date --date="$END_DATE" +%s || true)
            SIGNATURE_LINES=$(grep -A 1 "Signature Value:" "$CERT_LOG" | grep -v "Signature Value" | grep -v "-")
            SIGNATURE_LINE=$(echo "$SIGNATURE_LINES" | awk -v cnt="$NESTED_CERT_CNT" 'NR==cnt')
            TRIMMED_SIGNATURE_LINE=$(echo "$SIGNATURE_LINE" | cut -d ":" -f1-5 | xargs)
            CERT_DATES_ARR+=("$CERT_DATE")
            CERT_DATES_ARR_+=("$CERT_DATE_")
            SIGNATURE_LINES_ARR+=("$TRIMMED_SIGNATURE_LINE")
          done < "$LINE"
          for i in "${!CERT_DATES_ARR[@]}" ; do
            if [[ ${CERT_DATES_ARR_[$i]} -lt $CURRENT_DATE ]]; then
              print_output "  ${RED}${CERT_DATES_ARR[$i]} - $(print_path "$LINE") ${SIGNATURE_LINES_ARR[$i]} ${NC}" "" "$CERT_LOG"
              write_csv_log "$LINE" "${CERT_DATES_ARR_[$i]}" "yes"
              ((CERT_OUT_CNT+=1))
              ERROR_CODE=1
            elif [[ ${CERT_DATES_ARR_[$i]} -le $FUTURE_DATE ]]; then
              print_output "  ${ORANGE}${CERT_DATES_ARR[$i]} - $(print_path "$LINE") ${SIGNATURE_LINES_ARR[$i]} ${NC}" "" "$CERT_LOG"
              write_csv_log "$LINE" "${CERT_DATES_ARR_[$i]}" "expires within $CERT_EXPIRE_WATCH_DATE"
              ((CERT_WARNING_CNT+=1))
              ERROR_CODE=1
            else
              print_output "  ${GREEN}${CERT_DATES_ARR[$i]} - $(print_path "$LINE") ${SIGNATURE_LINES_ARR[$i]} ${NC}" "" "$CERT_LOG"
              write_csv_log "$LINE" "${CERT_DATES_ARR_[$i]}" "no"
            fi
          done
        else
          print_output "$(indent "$(orange "$(print_path "$LINE")")")"
          write_csv_log "$LINE" "unknown" "unknown"
        fi
      fi
    done
    write_log ""
    write_log "[*] Statistics:$TOTAL_CERT_CNT:$CERT_OUT_CNT:$CERT_WARNING_CNT"
  else
    print_output "[-] No certification files found"
  fi

  module_end_log "${FUNCNAME[0]}" "$TOTAL_CERT_CNT"
  
  return $ERROR_CODE
}
