#!/bin/sh -l

echo "Hello $1"
time=$(date)
echo "::set-output name=time::$time"

post_to_github () {
  if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    GITHUB_SHA=$(cat $GITHUB_EVENT_PATH | jq -r .pull_request.head.sha)
  fi

  if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN is required to post comment to GitHub"
  else
    echo "Posting comment to GitHub commit $GITHUB_SHA"
    msg="build_msg true"
    jq -Mnc --arg msg "$msg" '{"body": "Namespace Isolation policy violated: \"Services should not be allowed to communicate across namespaces\". \n Violating Rule(s): [\nINGRESS Selected: Health-Analytics FROM: Test-Application\n]"}' | curl -L -X POST -d @- \
      -H "Content-Type: application/json" \
      -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/comments"
  fi
}

post_to_github
