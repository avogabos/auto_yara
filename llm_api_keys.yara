looks liek this one is working for me:

rule DetectAPIKeys {
    meta:
        description = "Detect OpenAI, Anthropic, and Google API keys"
        author = "gbs"
        date = "2024-11-24"
        provider_1 = "OpenAI"
        provider_2 = "Anthropic"
        provider_3 = "Google"

    strings:
        // OpenAI API keys (sk-proj- and sk-svcacct-)
        $openai_key = /(sk-proj-|sk-svcacct-)[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]*A/

        // Anthropic API keys (sk-ant-api03 and sk-ant-admin01)
        $anthropic_key = /sk-ant-(api03|admin01)-[A-Za-z0-9_-]{90,}/

        // Google API keys starting with 'AIzaSy' and specific length
        $google_api_key = /AIzaSy[A-Za-z0-9_-]{33,34}/

    condition:
        $openai_key or $anthropic_key or $google_api_key
}
