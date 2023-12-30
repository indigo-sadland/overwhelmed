# overwhelmed

Whois information parser. Supports 2 type of output: cmd and .docx (Requires API key). 

### API:
To Get a Metered License API Key in the Free Tier, sign up on https://cloud.unidoc.io

### Installation
`GO111MODULE=on`
`go get github.com/indigo-sadland/overwhelmed`

If you want to use .docx as output then you need to add your Metered License API Key into `config.txt`

### Usage:
`overwhelmed -domain example.com -out cmd`
