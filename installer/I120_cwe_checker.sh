#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs cwe-checker for EMBA

I120_cwe_checker() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    export INSTALL_APP_LIST=()

    print_tool_info "unzip" 1
    print_tool_info "git" 1
    print_tool_info "gcc" 1
    print_tool_info "curl" 1
    print_tool_info "make" 1
    print_tool_info "rust-all" 1
    print_tool_info "cargo" 1

    print_git_info "cwe-checker" "fkie-cad/cwe_checker" "cwe_checker is a suite of checks to detect common bug classes such as use of dangerous functions and simple integer overflows."
    echo -e "$ORANGE""cwe-checker will be downloaded.""$NC"
    print_file_info "OpenJDK" "OpenJDK for cwe-checker" "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.12%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.12_7.tar.gz" "external/jdk.tar.gz"
    print_file_info "GHIDRA" "Ghidra for cwe-checker" "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip" "external/ghidra.zip"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""These applications will be installed/updated!""$NC"
      ANSWER=("y")
    fi
 
    case ${ANSWER:0:1} in
      y|Y )
        echo
	apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
  
        if ! [[ -d ./external/cwe_checker ]]; then
          # cleanup first
          rm "$HOME"/.cargo -r -f
          rm "$HOME"/.config -r -f
          rm external/rustup -r -f

          # Java SDK for ghidra
          if [[ -d ./external/jdk ]] ; then rm -R ./external/jdk ; fi
          curl -L https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.12%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.12_7.tar.gz -Sf -o external/jdk.tar.gz
          mkdir external/jdk 2>/dev/null
          tar -xzf external/jdk.tar.gz -C external/jdk --strip-components 1
          rm external/jdk.tar.gz

          # Ghidra
          if [[ -d ./external/ghidra ]] ; then rm -R ./external/ghidra ; fi
          curl -L https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip -Sf -o external/ghidra.zip
          mkdir external/ghidra 2>/dev/null
          unzip -qo external/ghidra.zip -d external/ghidra
          if [[ "$IN_DOCKER" -eq 1 ]]; then
            sed -i s@JAVA_HOME_OVERRIDE=@JAVA_HOME_OVERRIDE=/external/jdk@g external/ghidra/ghidra_10.1.2_PUBLIC/support/launch.properties
          else
            sed -i s@JAVA_HOME_OVERRIDE=@JAVA_HOME_OVERRIDE=external/jdk@g external/ghidra/ghidra_10.1.2_PUBLIC/support/launch.properties
          fi
          rm external/ghidra.zip

          if [[ -d ./external/cwe_checker ]] ; then rm -R ./external/cwe_checker ; fi
          mkdir ./external/cwe_checker 2>/dev/null
          git clone https://github.com/fkie-cad/cwe_checker.git external/cwe_checker
          cd external/cwe_checker || ( echo "Could not install EMBA component cwe_checker" && exit 1 )
          make all GHIDRA_PATH="$HOME_PATH""/external/ghidra/ghidra_10.1.2_PUBLIC"
          cd "$HOME_PATH" || ( echo "Could not install EMBA component cwe_checker" && exit 1 )

          if [[ "$IN_DOCKER" -eq 1 ]]; then
            cp -pr "$HOME""/.cargo/bin" "external/cwe_checker/bin"
            echo '{"ghidra_path":"/external/ghidra/ghidra_10.1.2_PUBLIC"}' > /root/.config/cwe_checker/ghidra.json

            # save .config as we remount /root with tempfs -> now we can restore it in the module
            cp -pr /root/.config ./external/cwe_checker/
            cp -pr /root/.local ./external/cwe_checker/
          fi

	  if [[ "$IN_DOCKER" -eq 1 ]]; then
            # cleanup
            rm "$HOME"/.cargo -r -f || true
            rm "$HOME"/.config -r -f || true
	  fi
        else
          echo -e "\\n""$GREEN""cwe-checker already installed - no further action performed.""$NC"
        fi
      ;;
    esac
  fi
} 