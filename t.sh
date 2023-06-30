#!/bin/bash
#
#/ Usage: script.sh [OPTIONS]... [ARGUMENTS]...
#/
#/ OPTIONS
#/   -h
#/       Print this help message
#/   -v
#/       Verbose mode
#/

# Bash setting: +x disables debugging, -x enables debugging
set +x

function help() {
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: scriptTemplate [-h|v]"
   echo "options:"
   echo "h     Print this Help"
   echo "v     Verbose mode"
   echo
}

function confluenceHeading() {
    #/ Usage: confluenceHeading arg1 arg2
    #/
    #/ ARGUMENTS
    #/   arg1
    #/     Type of heading (h1-h6)
    #/       E.g. h2
    #/   arg2
    #/     Heading text
    #/       E.g. "Test Heading"

    cHead="<$1>$2</$1><p>"
    echo $cHead
}

function confluenceLine() {
    #/ Usage: confluenceLine arg1
    #/
    #/ ARGUMENTS
    #/   arg1
    #/     Line text
    #/       E.g. "this is a line"

    cLine="<br />$1"
    echo $cLine
}

function confluenceSpaceId () {
    cId=$(curl --silent --show-error -U $1:$2 $3/space/$4 | jq -r '.id')
    echo $cId
}

function confluencePageId () {
    cPId=$(curl --silent --show-error -U $1:$2 "$3/content?title=$4" | jq -r .results[0].id)
    echo $cPId
}

function main() {
    # Set the cloud settings
    if [[ $TYPE == "detailed" ]]; then
        gcloud auth list
    fi
    gcloud config set project $project_id && printf "\nOK" || exit

    # Get a sorted list of all the projects in GCP
    gcp_projects=$(gcloud projects list \
        --format="value(name)" \
        --sort-by=name)

    # Get all the firewall rules with 'svpc' in the name
    microseg_fw_rules=$(gcloud compute firewall-rules list \
        --format="value(name)" \
        --filter="name~'svpc'")

    # Verbose output of projects and rules for troubleshooting
    if [[ $TYPE == "detailed" ]]; then
        bash --version
        printf "\n${BLUE}------------------------------------------- Available Projects ----------------------------------------${RESET}\n"

        for project in ${gcp_projects[@]}; do
            printf "\n${YELLOW_BOLD}Project:${RESET} $project"
        done

        printf "\n"
        printf "\n${BLUE}------------------------------------------- Available Microseg Rules ----------------------------------${RESET}\n"

        for fw_rule in ${microseg_fw_rules[@]}; do
            printf "\n${YELLOW_BOLD}Rule:${RESET} $fw_rule"
        done
    fi
    printf "\n"

    # Create an empty array
    declare -a col_projects
    
    # Loop through the FW Rules and extract the project name from the rule name for matching later
    for fw_rule in ${microseg_fw_rules[@]}; do
        if [[ $fw_rule =~ "deny" ]]; then
            [[ $fw_rule =~ ^svpc-p1-ufw-([a-z\-]+)-([a-z]{3}[0-9]{0,1})-deny-(base|gcp)-in$ ]]

            # rearrange the env and app to recreate the project name in GCP (as they are created using a standard method)
            cat_proj="${BASH_REMATCH[2]}-proj-${BASH_REMATCH[1]}"

            # verbose logging
            if [[ $TYPE == "detailed" ]]; then
                printf "\n${BLUE}$fw_rule --- ${RESET}" ; printf "$cat_proj"
            fi
            
            # Append the recreated project name to an array
            col_projects+=("$cat_proj")
        fi
    done
    printf "\n"

    # Sort the array of recreated project names
    IFS=$'\n' sorted=($(sort <<<"${col_projects[*]}"))
    unset IFS

    # Remove the duplicates from the recreated project names (due to multiple FW rules)
    unset dupes # ensure it's empty
    declare -A dupes

    for i in "${sorted[@]}"; do
        if [[ -z ${dupes[$i]} ]]; then
            unique_projects+=("$i")
        fi
        dupes["$i"]=1
    done
    unset dupes

    # Loop through already migrated rules, create the new confluence page content in string "new_content" and append as you go.
    timestamp=$(date "+%Y-%m-%d %T")
    new_content="$(confluenceHeading h2 "Projects in GCP already migrated")"
    new_content+="<br />Updated: $timestamp (UTC)"
    new_content+="<br />"
    printf "\n${GREEN} ## Projects in GCP already migrated. ${RESET}\n"
    for proj in ${unique_projects[@]}; do
        printf "\nMIGRATED: $proj"
        new_content+=$(confluenceLine "MIGRATED: $proj")
    done

    printf "\n\n${GREEN} ## Outstanding Projects in GCP NOT yet migrated. ${RESET}\n"
    new_content+="</p><h2>Outstanding Projects in GCP NOT yet migrated</h2><p />"
    
    # Compare the two arrays and extract the list of unique values
    unique_values=$(echo "${gcp_projects[@]} ${unique_projects[@]}" | tr ' ' '\n' | sort | uniq -u)

    # Sort the unique values and store them in a variable
    sorted_unique_values=$(echo "${unique_values[@]}" | sort)

    # Print the sorted unique values
    if [[ $TYPE == "detailed" ]]; then
        echo "${sorted_unique_values[@]}"
    fi

    # Add the string "NOT MIGRATED" before each line in sorted_unique_values
    for value in ${sorted_unique_values[@]}; do
        printf "\nNOT MIGRATED: $value"
        new_content+=$(confluenceLine "NOT MIGRATED: $value")
    done

    printf "\n\n"

    if [[ $TYPE == "detailed" ]]; then
        printf "\n\n${YELLOW_BOLD}$new_content${RESET}\n"
    fi
    
    # Get the Space ID (913703021) from the Space Name (NWMPE)
    nwmpe_id=$(confluenceSpaceId $CONFLUENCE_USER $CONFLUENCE_TOKEN $confluence_url $space_name)
    if [[ $TYPE == "detailed" ]]; then
        printf "\n\nNWMPE_ID          : $nwmpe_id"
    fi

    # Get the page ID (1302325118) from the page name
    microseg_page_id=$(confluencePageId $CONFLUENCE_USER $CONFLUENCE_TOKEN $confluence_url $page_to_update)
    if [[ $TYPE == "detailed" ]]; then
        printf "\nPAGE_ID           : $microseg_page_id"
    fi

    # Get the current version of the page
    old_version=$(curl --silent -U $CONFLUENCE_USER:$CONFLUENCE_TOKEN $confluence_url/content/$microseg_page_id?expand=version.number | jq -r '.version.number')
    if [[ $TYPE == "detailed" ]]; then
        printf "\nOLD_PAGE_VER      : $old_version"
    fi

    # Increment the version by 1 for the new page content
    version=$((old_version+1))
    if [[ $TYPE == "detailed" ]]; then
        printf "\nNew page version  : $version\n"
        printf "Confluence URL    : $confluence_url\n"
        printf "Confluence URL_v2 : $confluence_url_v2\n"
        printf "CONFLUENCE USER   : $CONFLUENCE_USER\n"
        printf "CONFLUENCE TOKEN  : $(echo $CONFLUENCE_TOKEN | cut -c1-10)...<snipped>...\n"
        printf "Page to update    : $page_to_update\n"
    fi

    printf "\n"

    # Update the page with the new content
    curl --silent --show-error \
        --request PUT \
        --url "$confluence_url_v2/pages/$microseg_page_id" \
        --user "$CONFLUENCE_USER:$CONFLUENCE_TOKEN" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data "{
            \"id\": \"$microseg_page_id\",
            \"status\": \"current\",
            \"title\": \"$page_to_update\",
            \"spaceId\": \"$nwmpe_id\",
            \"body\": {
            \"representation\": \"storage\",
            \"value\": \"$new_content\"
        },
        \"version\": {
            \"number\": $version,
            \"message\": \"Run from https://blah.com\"
        }
    }"
    printf "\n"
}
            
function settings() {
   # Get the options
   while getopts ":hv" option; do
      case $option in
         h) # display Help
            help
            exit;;
         v) # Verbose mode
            TYPE="detailed";;
      \?) # Invalid option
            echo "Error: Invalid option, run with -h for options"
            exit;;
      esac
   done
}

# GCP Project containing Firewall Rules
project_id="faking-animal-123456"

# Define the Confluence URL (user and token obtained from CICD vars)
confluence_url="https://url.atlassian.net/wiki/rest/api"
confluence_url_v2="https://url.atlassian.net/wiki/api/v2"
page_to_update="GCP-Progress-Report"
space_name="XXXXX"

# Colors
RED="\033[31m"
RED_BOLD="\033[31;1m"
YELLOW_BOLD="\033[33;1m"
GREEN="\033[32m"
ORANGE="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
MAGENTA="\033[35m"
LIGHT_GRAY="\033[37m"
BLACK="\033[30m"
RESET="\033[0m"

settings "$@"
main "$@"
