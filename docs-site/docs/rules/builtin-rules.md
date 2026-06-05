---
title: "Built-in Rules List"
description: "Complete list of all 954 built-in secret detection rules in Kingfisher. Searchable and filterable by provider, confidence level, and validation support."
---

# Built-in Rules

Kingfisher ships with **954 detection rules** across **584 providers**
(830 detectors + 124 dependent rules).
Of these, **489** include live validation and **50** support direct revocation.

!!! tip "Search"
    Use the search box below to filter rules by provider name, rule ID, or confidence level.

<input type="text" class="rules-search" placeholder="Search rules... (e.g. github, aws, anthropic)" />
<div class="rules-count"></div>

<table class="rules-table">
<thead>
<tr>
<th>Provider</th>
<th>Rule Name</th>
<th>Rule ID</th>
<th>Confidence</th>
<th>Validates</th>
<th>Revokes</th>
</tr>
</thead>
<tbody>
<tr>
<td>Ably</td>
<td>Ably API Key</td>
<td><code>kingfisher.ably.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Abstractapi</td>
<td>AbstractAPI API Key</td>
<td><code>kingfisher.abstractapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Abuseipdb</td>
<td>AbuseIPDB API Key</td>
<td><code>kingfisher.abuseipdb.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Adafruitio</td>
<td>Adafruit IO Key</td>
<td><code>kingfisher.adafruitio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Adobe</td>
<td>Adobe Stock API Key</td>
<td><code>kingfisher.adobe.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Adobe</td>
<td>Adobe IO Product ID</td>
<td><code>kingfisher.adobe.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Adobe</td>
<td>Adobe OAuth Client Secret</td>
<td><code>kingfisher.adobe.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Adobe</td>
<td>Adobe OAuth Client ID</td>
<td><code>kingfisher.adobe.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Age</td>
<td>Age Recipient (X25519 public key)</td>
<td><code>kingfisher.age.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Age</td>
<td>Age Identity (X22519 secret key)</td>
<td><code>kingfisher.age.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Age</td>
<td>Age Recipient (MLKEM768-X25519 public key)</td>
<td><code>kingfisher.age.3</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Age</td>
<td>Age Identity (MLKEM768-X25519 secret key)</td>
<td><code>kingfisher.age.4</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Agora</td>
<td>Agora App ID</td>
<td><code>kingfisher.agora.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Agora</td>
<td>Agora App Certificate</td>
<td><code>kingfisher.agora.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ai21</td>
<td>AI21 Studio API Key</td>
<td><code>kingfisher.ai21studio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ai71</td>
<td>AI71 API Key</td>
<td><code>kingfisher.ai71.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aikido</td>
<td>Aikido CI Token</td>
<td><code>kingfisher.aikido.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aikido</td>
<td>Aikido Client ID</td>
<td><code>kingfisher.aikido.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Aikido</td>
<td>Aikido Client Secret</td>
<td><code>kingfisher.aikido.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Airbrake</td>
<td>Airbrake User Key</td>
<td><code>kingfisher.airbrake.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Airtable</td>
<td>Airtable Personal Access Token</td>
<td><code>kingfisher.airtable.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Airtable</td>
<td>Airtable OAuth Token</td>
<td><code>kingfisher.airtable.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aiven</td>
<td>Aiven API Key</td>
<td><code>kingfisher.aiven.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Akamai</td>
<td>Akamai API Client Token</td>
<td><code>kingfisher.akamai.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Akamai</td>
<td>Akamai API Client Secret</td>
<td><code>kingfisher.akamai.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Akamai</td>
<td>Akamai API Access Token</td>
<td><code>kingfisher.akamai.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Akamai</td>
<td>Akamai API Host</td>
<td><code>kingfisher.akamai.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Alchemy</td>
<td>Alchemy API Key</td>
<td><code>kingfisher.alchemy.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Algolia</td>
<td>Algolia Admin API Key</td>
<td><code>kingfisher.algolia.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Algolia</td>
<td>Algolia Application ID</td>
<td><code>kingfisher.algolia.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Alibaba</td>
<td>Alibaba Access Key ID</td>
<td><code>kingfisher.alibabacloud.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Alibaba</td>
<td>Alibaba Access Key Secret</td>
<td><code>kingfisher.alibabacloud.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Alibaba</td>
<td>Alibaba STS Access Key ID</td>
<td><code>kingfisher.alibabacloud.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Alibaba</td>
<td>Alibaba STS Security Token</td>
<td><code>kingfisher.alibabacloud.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Alibaba</td>
<td>Alibaba STS Access Key Secret</td>
<td><code>kingfisher.alibabacloud.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Amazonmws</td>
<td>Amazon MWS Auth Token</td>
<td><code>kingfisher.amazonmws.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Amazonoauth</td>
<td>Login with Amazon OAuth Client ID</td>
<td><code>kingfisher.amazonoauth.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Amplitude</td>
<td>Amplitude Secret Key</td>
<td><code>kingfisher.amplitude.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Anthropic</td>
<td>Anthropic API Key</td>
<td><code>kingfisher.anthropic.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Anthropic</td>
<td>Anthropic Admin API Key</td>
<td><code>kingfisher.anthropic.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Anypoint</td>
<td>Anypoint API Key</td>
<td><code>kingfisher.anypoint.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Anypoint</td>
<td>Anypoint OAuth Client ID</td>
<td><code>kingfisher.anypoint.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Anypoint</td>
<td>Anypoint OAuth Client Secret</td>
<td><code>kingfisher.anypoint.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Apify</td>
<td>Apify API Token</td>
<td><code>kingfisher.apify.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Apollo</td>
<td>Apollo API Key</td>
<td><code>kingfisher.apollo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Appcenter</td>
<td>Visual Studio App Center API Token</td>
<td><code>kingfisher.appcenter.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Arcjet</td>
<td>Arcjet API Key</td>
<td><code>kingfisher.arcjet.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Artifactory</td>
<td>Artifactory Access Token</td>
<td><code>kingfisher.artifactory.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Artifactory</td>
<td>Artifactory JFrog URL</td>
<td><code>kingfisher.artifactory.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Artifactory</td>
<td>Artifactory Identity Reference Token</td>
<td><code>kingfisher.artifactory.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Artifactory</td>
<td>Artifactory NPM Auth (base64)</td>
<td><code>kingfisher.artifactory.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Asaas</td>
<td>Asaas API Token</td>
<td><code>kingfisher.asaas.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Asana</td>
<td>Asana Client ID</td>
<td><code>kingfisher.asana.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Asana</td>
<td>Asana Client Secret</td>
<td><code>kingfisher.asana.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Asana</td>
<td>Asana OAuth / Personal Access Token (Legacy)</td>
<td><code>kingfisher.asana.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Asana</td>
<td>Asana OAuth / Personal Access Token (V1)</td>
<td><code>kingfisher.asana.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Asana</td>
<td>Asana OAuth / Personal Access Token (V2)</td>
<td><code>kingfisher.asana.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Assemblyai</td>
<td>AssemblyAI API Key</td>
<td><code>kingfisher.assemblyai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Atlassian</td>
<td>Atlassian API token</td>
<td><code>kingfisher.atlassian.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Atlassian</td>
<td>Atlassian Admin API Key</td>
<td><code>kingfisher.atlassian.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Auth</td>
<td>HTTP Basic Authorization Header</td>
<td><code>kingfisher.auth.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Auth</td>
<td>HTTP Bearer Authorization Header (non-JWT)</td>
<td><code>kingfisher.auth.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Auth0</td>
<td>Auth0 Client ID</td>
<td><code>kingfisher.auth0.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Auth0</td>
<td>Auth0 Client Secret</td>
<td><code>kingfisher.auth0.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Auth0</td>
<td>Auth0 Domain</td>
<td><code>kingfisher.auth0.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Authress</td>
<td>Authress Service Client Access Key</td>
<td><code>kingfisher.authress.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aviationstack</td>
<td>AviationStack API Key</td>
<td><code>kingfisher.aviationstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aws</td>
<td>AWS Access Key ID</td>
<td><code>kingfisher.aws.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Aws</td>
<td>AWS Secret Access Key</td>
<td><code>kingfisher.aws.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Aws</td>
<td>AWS Session Token</td>
<td><code>kingfisher.aws.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Aws</td>
<td>AWS Bedrock API Key (Short-lived)</td>
<td><code>kingfisher.aws.6</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Aws</td>
<td>AWS Bedrock API Key (Long-lived)</td>
<td><code>kingfisher.aws.bedrock.long_lived</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Axiom</td>
<td>Axiom API Token</td>
<td><code>kingfisher.axiom.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Axiom</td>
<td>Axiom Personal Access Token</td>
<td><code>kingfisher.axiom.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure Connection String</td>
<td><code>kingfisher.azure.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure App Configuration Connection String</td>
<td><code>kingfisher.azure.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure Personal Access Token</td>
<td><code>kingfisher.azure.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure Container Registry URL</td>
<td><code>kingfisher.azure.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure Container Registry Password</td>
<td><code>kingfisher.azure.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azure</td>
<td>Azure AD Client Secret (Microsoft Entra ID)</td>
<td><code>kingfisher.azure.6</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure Notification Hub</td>
<td>Azure Notification Hub Namespace Host</td>
<td><code>kingfisher.azure.notificationhub.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure Notification Hub</td>
<td>Azure Notification Hub Name</td>
<td><code>kingfisher.azure.notificationhub.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure Notification Hub</td>
<td>Azure Notification Hub SAS Key Name</td>
<td><code>kingfisher.azure.notificationhub.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azure Notification Hub</td>
<td>Azure Notification Hub Access Key</td>
<td><code>kingfisher.azure.notificationhub.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azureapim</td>
<td>Azure API Management Subscription Key</td>
<td><code>kingfisher.azureapim.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azureapim</td>
<td>Azure API Management Gateway URL</td>
<td><code>kingfisher.azureapim.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurebatch</td>
<td>Azure Batch Account Key</td>
<td><code>kingfisher.azurebatch.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azurebatch</td>
<td>Azure Batch Account Endpoint</td>
<td><code>kingfisher.azurebatch.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurecognitive</td>
<td>Azure Cognitive Services / AI Services Key</td>
<td><code>kingfisher.azurecognitive.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurecommunication</td>
<td>Azure Communication Services Connection String</td>
<td><code>kingfisher.azurecommunication.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurecosmosdb</td>
<td>Azure CosmosDB Account Key</td>
<td><code>kingfisher.azurecosmosdb.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurecosmosdb</td>
<td>Azure CosmosDB Connection String</td>
<td><code>kingfisher.azurecosmosdb.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuredevops</td>
<td>Azure DevOps Organization</td>
<td><code>kingfisher.azure.devops.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuredevops</td>
<td>Azure DevOps Personal Access Token</td>
<td><code>kingfisher.azure.devops.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azureeventgrid</td>
<td>Azure Event Grid Key</td>
<td><code>kingfisher.azureeventgrid.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurefunctionkey</td>
<td>Azure Function Key in URL</td>
<td><code>kingfisher.azurefunctionkey.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azurefunctionkey</td>
<td>Azure Function Master/Host Key</td>
<td><code>kingfisher.azurefunctionkey.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurelogicapps</td>
<td>Azure Logic Apps SAS URL</td>
<td><code>kingfisher.azurelogicapps.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuremaps</td>
<td>Azure Maps Subscription Key</td>
<td><code>kingfisher.azuremaps.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuremixedreality</td>
<td>Azure Mixed Reality / Spatial Anchors Key</td>
<td><code>kingfisher.azuremixedreality.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azureopenai</td>
<td>Azure OpenAI API Key</td>
<td><code>kingfisher.azureopenai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azureopenai</td>
<td>Azure OpenAI Host</td>
<td><code>kingfisher.azureopenai.host.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuresastoken</td>
<td>Azure SAS Token</td>
<td><code>kingfisher.azuresastoken.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuresastoken</td>
<td>Azure SAS Token in URL</td>
<td><code>kingfisher.azuresastoken.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuresearchquery</td>
<td>Azure Search Query Key</td>
<td><code>kingfisher.azuresearch.key.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuresearchquery</td>
<td>Azure Search URL</td>
<td><code>kingfisher.azuresearch.url.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuresignalr</td>
<td>Azure SignalR Connection String</td>
<td><code>kingfisher.azuresignalr.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurespeech</td>
<td>Azure Speech Region</td>
<td><code>kingfisher.azurespeech.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurespeech</td>
<td>Azure Speech API Key</td>
<td><code>kingfisher.azurespeech.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuresql</td>
<td>Azure SQL Connection String</td>
<td><code>kingfisher.azuresql.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuresql</td>
<td>Azure SQL Password Assignment</td>
<td><code>kingfisher.azuresql.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurestorage</td>
<td>Azure Storage Account Name</td>
<td><code>kingfisher.azurestorage.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azurestorage</td>
<td>Azure Storage Account Key</td>
<td><code>kingfisher.azurestorage.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azuretranslator</td>
<td>Azure Translator Region</td>
<td><code>kingfisher.azuretranslator.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Azuretranslator</td>
<td>Azure Translator API Key</td>
<td><code>kingfisher.azuretranslator.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Azurewebpubsub</td>
<td>Azure Web PubSub Connection String</td>
<td><code>kingfisher.azurewebpubsub.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Baremetrics</td>
<td>Baremetrics API Key</td>
<td><code>kingfisher.baremetrics.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Baseten</td>
<td>Baseten API Key</td>
<td><code>kingfisher.baseten.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Beamer</td>
<td>Beamer API token</td>
<td><code>kingfisher.beamer.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Betterstack</td>
<td>Better Stack API Token</td>
<td><code>kingfisher.betterstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Bitbucket</td>
<td>Bitbucket Client ID</td>
<td><code>kingfisher.bitbucket.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Bitbucket</td>
<td>Bitbucket Secret</td>
<td><code>kingfisher.bitbucket.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Bitfinex</td>
<td>Bitfinex API Key</td>
<td><code>kingfisher.bitfinex.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Bitfinex</td>
<td>Bitfinex API Secret</td>
<td><code>kingfisher.bitfinex.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Bitly</td>
<td>Bitly Access Token</td>
<td><code>kingfisher.bitly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Bitrise</td>
<td>Bitrise Personal Access Token</td>
<td><code>kingfisher.bitrise.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blockprotocol</td>
<td>Block Protocol API Key</td>
<td><code>kingfisher.blockprotocol.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Device Access Token</td>
<td><code>kingfisher.blynk.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Cloud Host</td>
<td><code>kingfisher.blynk.10</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk OAuth Client ID</td>
<td><code>kingfisher.blynk.11</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Organization Access Token</td>
<td><code>kingfisher.blynk.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Organization Access Token</td>
<td><code>kingfisher.blynk.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Organization Client Credentials</td>
<td><code>kingfisher.blynk.8</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Blynk</td>
<td>Blynk Organization Client Credentials</td>
<td><code>kingfisher.blynk.9</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Box</td>
<td>Box API Access Token</td>
<td><code>kingfisher.box.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Braintree</td>
<td>Braintree Tokenization Key</td>
<td><code>kingfisher.braintree.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Branchio</td>
<td>Branch.io Live Key</td>
<td><code>kingfisher.branchio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Branchio</td>
<td>Branch.io Test Key</td>
<td><code>kingfisher.branchio.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Branchio</td>
<td>Branch.io Secret</td>
<td><code>kingfisher.branchio.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Brave</td>
<td>Brave Search API Key</td>
<td><code>kingfisher.brave.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Brevo</td>
<td>Brevo API Token</td>
<td><code>kingfisher.brevo.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Browserstack</td>
<td>BrowserStack Access Key</td>
<td><code>kingfisher.browserstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Browserstack</td>
<td>BrowserStack Username</td>
<td><code>kingfisher.browserstack.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Browseruse</td>
<td>Browser Use API Key</td>
<td><code>kingfisher.browseruse.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Builderio</td>
<td>Builder.io Private API Key</td>
<td><code>kingfisher.builderio.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Buildkite</td>
<td>Buildkite API Key</td>
<td><code>kingfisher.buildkite.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Bunnynet</td>
<td>Bunny.net API Key</td>
<td><code>kingfisher.bunnynet.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Buttercms</td>
<td>ButterCMS API Key</td>
<td><code>kingfisher.buttercms.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Calcom</td>
<td>Cal.com API Key</td>
<td><code>kingfisher.calcom.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Calendly</td>
<td>Calendly Personal Access Token</td>
<td><code>kingfisher.calendly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Canva</td>
<td>Canva Connect API Client Secret</td>
<td><code>kingfisher.canva.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Canva</td>
<td>Canva Connect API Client ID</td>
<td><code>kingfisher.canva.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Carto</td>
<td>CARTO API Access Token (JWT)</td>
<td><code>kingfisher.carto.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Censys</td>
<td>Censys API ID</td>
<td><code>kingfisher.censys.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Censys</td>
<td>Censys API Secret</td>
<td><code>kingfisher.censys.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cerebras</td>
<td>Cerebras AI API Key</td>
<td><code>kingfisher.cerebras.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cfxre</td>
<td>Cfx.re FiveM Server Key</td>
<td><code>kingfisher.cfxre.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Chartmogul</td>
<td>ChartMogul API Key</td>
<td><code>kingfisher.chartmogul.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Checkout</td>
<td>Checkout.com Secret Key</td>
<td><code>kingfisher.checkout.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Checkout</td>
<td>Checkout.com Sandbox Secret Key</td>
<td><code>kingfisher.checkout.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Circleci</td>
<td>CircleCI API Personal Access Token</td>
<td><code>kingfisher.circleci.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Circleci</td>
<td>CircleCI API Project Token</td>
<td><code>kingfisher.circleci.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ciscomeraki</td>
<td>Cisco Meraki API Key</td>
<td><code>kingfisher.ciscomeraki.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clarifai</td>
<td>Clarifai API Key</td>
<td><code>kingfisher.clarifai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clay</td>
<td>Clay API Key</td>
<td><code>kingfisher.clay.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Clearbit</td>
<td>Clearbit API Key</td>
<td><code>kingfisher.clearbit.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clearout</td>
<td>Clearout API Token</td>
<td><code>kingfisher.clearout.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clerk</td>
<td>Clerk Secret Key</td>
<td><code>kingfisher.clerk.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clickhouse</td>
<td>ClickHouse Cloud Secret Key</td>
<td><code>kingfisher.clickhouse.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clickhouse</td>
<td>ClickHouse Cloud Key ID</td>
<td><code>kingfisher.clickhouse.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Clickup</td>
<td>ClickUp Personal API Token</td>
<td><code>kingfisher.clickup.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clockwork</td>
<td>Clockwork SMS API Key</td>
<td><code>kingfisher.clockwork.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Clojars</td>
<td>Clojars Username</td>
<td><code>kingfisher.clojars.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Clojars</td>
<td>Clojars API Token</td>
<td><code>kingfisher.clojars.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Closecrm</td>
<td>Close CRM API Key</td>
<td><code>kingfisher.closecrm.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cloudant</td>
<td>IBM Cloudant Legacy Credentials</td>
<td><code>kingfisher.cloudant.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Cloudflare</td>
<td>Cloudflare API Token</td>
<td><code>kingfisher.cloudflare.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Cloudflare</td>
<td>Cloudflare CA Key</td>
<td><code>kingfisher.cloudflare.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cloudflare</td>
<td>Cloudflare User API Token (cfut_ prefix)</td>
<td><code>kingfisher.cloudflare.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cloudinary</td>
<td>Cloudinary API Secret</td>
<td><code>kingfisher.cloudinary.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cloudinary</td>
<td>Cloudinary API Key</td>
<td><code>kingfisher.cloudinary.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Cloudinary</td>
<td>Cloudinary Cloud Name</td>
<td><code>kingfisher.cloudinary.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Cloudsight</td>
<td>CloudSight API Key</td>
<td><code>kingfisher.cloudsight.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cockroachlabs</td>
<td>CockroachDB Cloud Service Account API Key</td>
<td><code>kingfisher.cockroachlabs.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Codacy</td>
<td>Codacy API Key</td>
<td><code>kingfisher.codacy.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Codeclimate</td>
<td>CodeClimate Reporter ID</td>
<td><code>kingfisher.codeclimate.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Codecov</td>
<td>Codecov Access Token</td>
<td><code>kingfisher.codecov.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coderabbit</td>
<td>CodeRabbit API Key</td>
<td><code>kingfisher.coderabbit.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cohere</td>
<td>Cohere API Key</td>
<td><code>kingfisher.cohere.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coinbase</td>
<td>Coinbase Access Token</td>
<td><code>kingfisher.coinbase.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coinbase</td>
<td>Coinbase CDP API Key (ECDSA)</td>
<td><code>kingfisher.coinbase.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coinbase</td>
<td>Coinbase CDP API Key (Ed25519)</td>
<td><code>kingfisher.coinbase.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coinlayer</td>
<td>Coinlayer API Key</td>
<td><code>kingfisher.coinlayer.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Composio</td>
<td>Composio Project API Key</td>
<td><code>kingfisher.composio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Composio</td>
<td>Composio Consumer API Key</td>
<td><code>kingfisher.composio.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Configcat</td>
<td>ConfigCat SDK Key</td>
<td><code>kingfisher.configcat.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Configcat</td>
<td>ConfigCat SDK Key (Extended)</td>
<td><code>kingfisher.configcat.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Confluence</td>
<td>Confluence Data Center Personal Access Token</td>
<td><code>kingfisher.confluence.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Confluence</td>
<td>Confluence Data Center Domain</td>
<td><code>kingfisher.confluence.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Confluent</td>
<td>Confluent Client ID</td>
<td><code>kingfisher.confluent.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Confluent</td>
<td>Confluent API Secret</td>
<td><code>kingfisher.confluent.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Confluent</td>
<td>Confluent API Secret - Updated Format</td>
<td><code>kingfisher.confluent.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Contentful</td>
<td>Contentful Delivery API Token</td>
<td><code>kingfisher.contentful.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Contentful</td>
<td>Contentful Personal Access Token</td>
<td><code>kingfisher.contentful.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Contentstack</td>
<td>Contentstack Management Token</td>
<td><code>kingfisher.contentstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Contentstack</td>
<td>Contentstack API Key</td>
<td><code>kingfisher.contentstack.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Convex</td>
<td>Convex Deploy Key</td>
<td><code>kingfisher.convex.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Convex</td>
<td>Convex Management Access Token</td>
<td><code>kingfisher.convex.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Couchbase</td>
<td>Couchbase Capella API Key</td>
<td><code>kingfisher.couchbase.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Courier</td>
<td>Courier API Key</td>
<td><code>kingfisher.courier.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coveralls</td>
<td>Coveralls Repo Identifier</td>
<td><code>kingfisher.coveralls.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Coveralls</td>
<td>Coveralls Personal API Token</td>
<td><code>kingfisher.coveralls.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Coze</td>
<td>Coze Personal Access Token</td>
<td><code>kingfisher.coze.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Crates.Io</td>
<td>crates.io API Key</td>
<td><code>kingfisher.cratesio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Credentials</td>
<td>Credentials in a URL</td>
<td><code>kingfisher.credentials.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Crossmint</td>
<td>Crossmint Server API Key</td>
<td><code>kingfisher.crossmint.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Crossmint</td>
<td>Crossmint Client API Key</td>
<td><code>kingfisher.crossmint.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Curl</td>
<td>Curl Basic Authentication Credentials</td>
<td><code>kingfisher.curl.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Curl</td>
<td>Curl Header Authentication</td>
<td><code>kingfisher.curl.2</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Currencylayer</td>
<td>Currencylayer API Key</td>
<td><code>kingfisher.currencylayer.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cursor</td>
<td>Cursor Integrations (User) API Key</td>
<td><code>kingfisher.cursor.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Customerio</td>
<td>Customer.io Tracking API Key</td>
<td><code>kingfisher.customerio.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Customerio</td>
<td>Customer.io App API Key</td>
<td><code>kingfisher.customerio.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cypress</td>
<td>Cypress Record Key</td>
<td><code>kingfisher.cypress.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Cypress</td>
<td>Cypress Project ID</td>
<td><code>kingfisher.cypress.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Daily</td>
<td>Daily API Key</td>
<td><code>kingfisher.daily.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Databento</td>
<td>Databento API Key</td>
<td><code>kingfisher.databento.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Databricks</td>
<td>Databricks API token</td>
<td><code>kingfisher.databricks.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Databricks</td>
<td>Databricks API Token</td>
<td><code>kingfisher.databricks.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Databricks</td>
<td>Databricks Domain</td>
<td><code>kingfisher.databricks.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Datadog</td>
<td>Datadog Site Domain</td>
<td><code>kingfisher.datadog.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Datadog</td>
<td>Datadog API Key</td>
<td><code>kingfisher.datadog.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Datadog</td>
<td>Datadog Application Key</td>
<td><code>kingfisher.datadog.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Datagov</td>
<td>Data.gov API Key</td>
<td><code>kingfisher.datagov.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Datastax</td>
<td>DataStax Astra Application Token</td>
<td><code>kingfisher.datastax.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Db2</td>
<td>IBM DB2 / AS400 Credentials</td>
<td><code>kingfisher.db2.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Deepgram</td>
<td>Deepgram API Key</td>
<td><code>kingfisher.deepgram.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Deepl</td>
<td>DeepL API Key (Free)</td>
<td><code>kingfisher.deepl.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Deepl</td>
<td>DeepL API Key (Pro)</td>
<td><code>kingfisher.deepl.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Deepseek</td>
<td>DeepSeek API Key</td>
<td><code>kingfisher.deepseek.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Definednetworking</td>
<td>Defined Networking API Token</td>
<td><code>kingfisher.definednetworking.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Delighted</td>
<td>Delighted API Key</td>
<td><code>kingfisher.delighted.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Deno</td>
<td>Deno Account Token</td>
<td><code>kingfisher.deno.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dependency Track</td>
<td>Dependency-Track API Key</td>
<td><code>kingfisher.dtrack.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Detectify</td>
<td>Detectify API Key</td>
<td><code>kingfisher.detectify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Devcycle</td>
<td>DevCycle Client SDK Key</td>
<td><code>kingfisher.devcycle.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Devcycle</td>
<td>DevCycle Mobile SDK Key</td>
<td><code>kingfisher.devcycle.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Devcycle</td>
<td>DevCycle Server SDK Key</td>
<td><code>kingfisher.devcycle.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Deviantart</td>
<td>DeviantArt Access Token</td>
<td><code>kingfisher.deviantart.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Devin</td>
<td>Cognition Devin Personal API Key</td>
<td><code>kingfisher.devin.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Devin</td>
<td>Cognition Devin Service API Key</td>
<td><code>kingfisher.devin.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Devin</td>
<td>Cognition Devin Service User Token</td>
<td><code>kingfisher.devin.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Diffbot</td>
<td>Diffbot API Key</td>
<td><code>kingfisher.diffbot.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dify</td>
<td>Dify API Key</td>
<td><code>kingfisher.dify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Digitalocean</td>
<td>DigitalOcean API Key</td>
<td><code>kingfisher.digitalocean.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Digitalocean</td>
<td>DigitalOcean Refresh Token</td>
<td><code>kingfisher.digitalocean.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Discord</td>
<td>Discord Webhook URL</td>
<td><code>kingfisher.discord.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Discord</td>
<td>Discord Bot Token</td>
<td><code>kingfisher.discord.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Discord</td>
<td>Discord Bot ID</td>
<td><code>kingfisher.discord.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Disqus</td>
<td>Disqus API Key</td>
<td><code>kingfisher.disqus.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Django</td>
<td>Django Secret Key</td>
<td><code>kingfisher.django.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Docker</td>
<td>Docker Registry Credentials (auths JSON)</td>
<td><code>kingfisher.docker.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Docker</td>
<td>Docker Swarm Join Token</td>
<td><code>kingfisher.docker.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Docker</td>
<td>Docker Swarm Unlock Key</td>
<td><code>kingfisher.docker.3</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Dockerhub</td>
<td>Docker Hub Personal Access Token</td>
<td><code>kingfisher.dockerhub.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dockerhub</td>
<td>Docker Hub Username</td>
<td><code>kingfisher.dockerhub.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Dockerhub</td>
<td>Docker Hub Organization Access Token</td>
<td><code>kingfisher.dockerhub.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Docusign</td>
<td>DocuSign API Secret Key</td>
<td><code>kingfisher.docusign.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Docusign</td>
<td>DocuSign Integration Key</td>
<td><code>kingfisher.docusign.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Docusign</td>
<td>DocuSign Auth Host</td>
<td><code>kingfisher.docusign.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Docusign</td>
<td>DocuSign Redirect URI</td>
<td><code>kingfisher.docusign.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler CLI Token</td>
<td><code>kingfisher.doppler.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler Personal Token</td>
<td><code>kingfisher.doppler.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler Service Token</td>
<td><code>kingfisher.doppler.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler Service Account Token</td>
<td><code>kingfisher.doppler.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler SCIM Token</td>
<td><code>kingfisher.doppler.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Doppler</td>
<td>Doppler Audit Token</td>
<td><code>kingfisher.doppler.6</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Droneci</td>
<td>DroneCI Access Token</td>
<td><code>kingfisher.drone.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dropbox</td>
<td>Dropbox API secret/key</td>
<td><code>kingfisher.dropbox.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dropbox</td>
<td>Dropbox Long-Lived API Token</td>
<td><code>kingfisher.dropbox.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dryrunsecurity</td>
<td>DryRun Security API Key</td>
<td><code>kingfisher.dryrunsecurity.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dub</td>
<td>Dub.co API Key</td>
<td><code>kingfisher.dub.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Duffel</td>
<td>Duffel API Token</td>
<td><code>kingfisher.duffel.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Duo</td>
<td>Duo Security Integration Key</td>
<td><code>kingfisher.duo.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Duo</td>
<td>Duo Security Secret Key</td>
<td><code>kingfisher.duo.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Duplocloud</td>
<td>DuploCloud API Key</td>
<td><code>kingfisher.duplocloud.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Dwolla</td>
<td>Dwolla Client ID</td>
<td><code>kingfisher.dwolla.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Dwolla</td>
<td>Dwolla Client Secret</td>
<td><code>kingfisher.dwolla.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Dwolla</td>
<td>Dwolla API Base URL</td>
<td><code>kingfisher.dwolla.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Dynatrace</td>
<td>Dynatrace Token</td>
<td><code>kingfisher.dynatrace.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>E2B</td>
<td>E2B API Key</td>
<td><code>kingfisher.e2b.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Easypost</td>
<td>EasyPost API token</td>
<td><code>kingfisher.easypost.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ebay</td>
<td>eBay Production Client ID</td>
<td><code>kingfisher.ebay.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ebay</td>
<td>eBay Sandbox Client ID</td>
<td><code>kingfisher.ebay.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ebay</td>
<td>eBay Client Secret</td>
<td><code>kingfisher.ebay.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Elastic</td>
<td>Elastic Cloud API Key</td>
<td><code>kingfisher.elastic.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Elastic</td>
<td>Elasticsearch API Key with Prefix</td>
<td><code>kingfisher.elastic.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Elasticemail</td>
<td>Elastic Email API Key</td>
<td><code>kingfisher.elasticemail.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Elevenlabs</td>
<td>ElevenLabs API Key</td>
<td><code>kingfisher.elevenlabs.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Endorlabs</td>
<td>Endor Labs API Key</td>
<td><code>kingfisher.endorlabs.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Endorlabs</td>
<td>Endor Labs API Secret</td>
<td><code>kingfisher.endorlabs.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Equinix</td>
<td>Equinix Metal / Packet API Token</td>
<td><code>kingfisher.equinix.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Eraserio</td>
<td>Eraser API Key</td>
<td><code>kingfisher.eraser.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Etsy</td>
<td>Etsy Open API Key</td>
<td><code>kingfisher.etsy.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Eventbrite</td>
<td>Eventbrite API Key</td>
<td><code>kingfisher.eventbrite.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Exaai</td>
<td>Exa AI API Key</td>
<td><code>kingfisher.exa.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Facebook</td>
<td>Facebook App ID</td>
<td><code>kingfisher.facebook.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Facebook</td>
<td>Facebook Secret Key</td>
<td><code>kingfisher.facebook.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Facebook</td>
<td>Facebook Access Token</td>
<td><code>kingfisher.facebook.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Falai</td>
<td>Fal.ai API Key</td>
<td><code>kingfisher.falai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Fastly</td>
<td>Fastly API token</td>
<td><code>kingfisher.fastly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fernet</td>
<td>Fernet Symmetric Encryption Key</td>
<td><code>kingfisher.fernet.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Figma</td>
<td>Figma Personal Access Token</td>
<td><code>kingfisher.figma.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Figma</td>
<td>Figma Personal Access Header Token</td>
<td><code>kingfisher.figma.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fileio</td>
<td>FileIO Secret Key</td>
<td><code>kingfisher.fileio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Filezilla</td>
<td>FileZilla base64 encoded password</td>
<td><code>kingfisher.filezilla.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Filezilla</td>
<td>FileZilla stored password (Pass plaintext)</td>
<td><code>kingfisher.filezilla.2</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Finicity</td>
<td>Finicity API token</td>
<td><code>kingfisher.finicity.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Finicity</td>
<td>Finicity client secret</td>
<td><code>kingfisher.finicity.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Finnhub</td>
<td>Finnhub API Token</td>
<td><code>kingfisher.finnhub.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Firebase</td>
<td>Firebase Cloud Messaging Server Key</td>
<td><code>kingfisher.firebase.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Firebase</td>
<td>Firebase Cloud Messaging Device Token</td>
<td><code>kingfisher.firebase.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Firecrawl</td>
<td>Firecrawl API Key</td>
<td><code>kingfisher.firecrawl.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fireworksai</td>
<td>Fireworks.ai API Key</td>
<td><code>kingfisher.fireworks.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fixer</td>
<td>Fixer.io API Key</td>
<td><code>kingfisher.fixer.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flagsmith</td>
<td>Flagsmith Organisation API Key</td>
<td><code>kingfisher.flagsmith.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flagsmith</td>
<td>Flagsmith Environment Key</td>
<td><code>kingfisher.flagsmith.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Fleetbase</td>
<td>Fleetbase API Key</td>
<td><code>kingfisher.fleetbase.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flickr</td>
<td>Flickr API Key</td>
<td><code>kingfisher.flickr.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flickr</td>
<td>Flickr OAuth Token</td>
<td><code>kingfisher.flickr.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flutterwave</td>
<td>Flutterwave Public Key</td>
<td><code>kingfisher.flutterwave.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Flutterwave</td>
<td>Flutterwave Secret Key</td>
<td><code>kingfisher.flutterwave.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Flyio</td>
<td>Fly.io API Token</td>
<td><code>kingfisher.flyio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Forestadmin</td>
<td>Forest Admin Auth Secret</td>
<td><code>kingfisher.forestadmin.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Foursquare</td>
<td>Foursquare Client ID</td>
<td><code>kingfisher.foursquare.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Foursquare</td>
<td>Foursquare Client Secret</td>
<td><code>kingfisher.foursquare.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Frameio</td>
<td>Frame.io API Token</td>
<td><code>kingfisher.frameio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Freemius</td>
<td>Freemius Secret Key</td>
<td><code>kingfisher.freemius.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Freshbooks</td>
<td>FreshBooks Access Token</td>
<td><code>kingfisher.freshbooks.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Freshdesk</td>
<td>Freshdesk Domain</td>
<td><code>kingfisher.freshdesk.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Freshdesk</td>
<td>Freshdesk API Key</td>
<td><code>kingfisher.freshdesk.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Friendli</td>
<td>Friendli.ai API Key</td>
<td><code>kingfisher.friendli.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ftp</td>
<td>FTP Connection URI Credentials</td>
<td><code>kingfisher.ftp.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fullcontact</td>
<td>FullContact API Key</td>
<td><code>kingfisher.fullcontact.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Fullstory</td>
<td>Fullstory API Key</td>
<td><code>kingfisher.fullstory.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gamma</td>
<td>Gamma API Key</td>
<td><code>kingfisher.gamma.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gcnotify</td>
<td>GC Notify API Key</td>
<td><code>kingfisher.gcnotify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gcp</td>
<td>GCP API Token</td>
<td><code>kingfisher.gcp.1</code></td>
<td>High</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Gcp</td>
<td>GCP Private Key ID</td>
<td><code>kingfisher.gcp.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gemfury</td>
<td>Gemfury Deploy or Push Token</td>
<td><code>kingfisher.gemfury.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gemfury</td>
<td>Gemfury Full Access Token</td>
<td><code>kingfisher.gemfury.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gemstash</td>
<td>Gemstash API Key</td>
<td><code>kingfisher.gemstash.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic Secret</td>
<td><code>kingfisher.generic.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic API Key</td>
<td><code>kingfisher.generic.2</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic Username and Password</td>
<td><code>kingfisher.generic.3</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic Username and Password</td>
<td><code>kingfisher.generic.4</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic Password</td>
<td><code>kingfisher.generic.5</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Weak Password Pattern</td>
<td><code>kingfisher.generic.6</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Generic Username and Password</td>
<td><code>kingfisher.generic.8</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Generic</td>
<td>Docker Robot Credentials (plaintext pair)</td>
<td><code>kingfisher.generic.9</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Geoapify</td>
<td>Geoapify API Key</td>
<td><code>kingfisher.geoapify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ghost</td>
<td>Ghost CMS Admin API Key</td>
<td><code>kingfisher.ghost.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ghost</td>
<td>Ghost CMS Content API Key</td>
<td><code>kingfisher.ghost.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitalk</td>
<td>Gitalk OAuth Credentials</td>
<td><code>kingfisher.gitalk.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitea</td>
<td>Gitea Access Token</td>
<td><code>kingfisher.gitea.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Github</td>
<td>GitHub Personal Access Token - fine-grained permissions</td>
<td><code>kingfisher.github.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub Personal Access Token</td>
<td><code>kingfisher.github.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub OAuth Access Token</td>
<td><code>kingfisher.github.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub App User-to-Server Token</td>
<td><code>kingfisher.github.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub App Server-to-Server Token</td>
<td><code>kingfisher.github.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub Refresh Token</td>
<td><code>kingfisher.github.6</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Github</td>
<td>GitHub Client ID</td>
<td><code>kingfisher.github.7</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Github</td>
<td>GitHub Legacy Secret Key</td>
<td><code>kingfisher.github.8</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Github</td>
<td>GitHub App Server-to-Server Token (stateless JWT format)</td>
<td><code>kingfisher.github.9</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Private Token</td>
<td><code>kingfisher.gitlab.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Kubernetes Agent Token</td>
<td><code>kingfisher.gitlab.10</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab OAuth Application Secret</td>
<td><code>kingfisher.gitlab.11</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Runner Authentication Token</td>
<td><code>kingfisher.gitlab.12</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Runner Authentication Token - Routable Format</td>
<td><code>kingfisher.gitlab.13</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab SCIM Token</td>
<td><code>kingfisher.gitlab.14</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Session Cookie</td>
<td><code>kingfisher.gitlab.15</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Runner Registration Token</td>
<td><code>kingfisher.gitlab.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Pipeline Trigger Token</td>
<td><code>kingfisher.gitlab.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Private Token - Routable Format</td>
<td><code>kingfisher.gitlab.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab CI/CD Job Token</td>
<td><code>kingfisher.gitlab.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Deploy Token</td>
<td><code>kingfisher.gitlab.6</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Feature Flag Client Token</td>
<td><code>kingfisher.gitlab.7</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Feed Token</td>
<td><code>kingfisher.gitlab.8</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitlab</td>
<td>GitLab Incoming Mail Token</td>
<td><code>kingfisher.gitlab.9</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gitter</td>
<td>Gitter Access Token</td>
<td><code>kingfisher.gitter.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Gocardless</td>
<td>GoCardless API Token</td>
<td><code>kingfisher.gocardless.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Godaddy</td>
<td>GoDaddy API Credentials</td>
<td><code>kingfisher.godaddy.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Google</td>
<td>Google Client ID</td>
<td><code>kingfisher.google.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Google</td>
<td>Google OAuth Client Secret</td>
<td><code>kingfisher.google.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Google</td>
<td>Google OAuth Client Secret</td>
<td><code>kingfisher.google.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Google</td>
<td>Google OAuth Access Token</td>
<td><code>kingfisher.google.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Google</td>
<td>Google OAuth Credentials</td>
<td><code>kingfisher.google.6</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Google</td>
<td>Google Gemini API Key</td>
<td><code>kingfisher.google.7</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Googleoauth2</td>
<td>Google OAuth2 Access Token</td>
<td><code>kingfisher.google.oauth2.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Gradle</td>
<td>Hardcoded Gradle Credentials</td>
<td><code>kingfisher.gradle.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Grafana</td>
<td>Grafana API Token</td>
<td><code>kingfisher.grafana.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Grafana</td>
<td>Grafana Cloud API Token</td>
<td><code>kingfisher.grafana.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Grafana</td>
<td>Grafana Service Account Token</td>
<td><code>kingfisher.grafana.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Grafana</td>
<td>Grafana Domain</td>
<td><code>kingfisher.grafana.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Groq</td>
<td>Groq API Key</td>
<td><code>kingfisher.groq.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Guardian</td>
<td>Guardian API Key</td>
<td><code>kingfisher.guardian.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Guardsquare</td>
<td>GuardSquare AppSweep API Key</td>
<td><code>kingfisher.guardsquare.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Gumroad</td>
<td>Gumroad Access Token</td>
<td><code>kingfisher.gumroad.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hackclub</td>
<td>Hack Club AI API Key</td>
<td><code>kingfisher.hackclub.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Harness</td>
<td>Harness Personal Access Token (PAT)</td>
<td><code>kingfisher.harness.pat.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (Kerberos 5, etype 23, AS-REP)</td>
<td><code>kingfisher.krb5.asrep.23.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (md5crypt)</td>
<td><code>kingfisher.pwhash.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (bcrypt)</td>
<td><code>kingfisher.pwhash.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (sha256crypt)</td>
<td><code>kingfisher.pwhash.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (sha512crypt)</td>
<td><code>kingfisher.pwhash.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashes</td>
<td>Password Hash (Cisco IOS PBKDF2 with SHA256)</td>
<td><code>kingfisher.pwhash.5</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Service Token (&lt; v1.10)</td>
<td><code>kingfisher.hashicorp.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Batch Token (&lt; v1.10)</td>
<td><code>kingfisher.hashicorp.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Recovery Token (&lt; v1.10)</td>
<td><code>kingfisher.hashicorp.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Service Token (&gt;= v1.10)</td>
<td><code>kingfisher.hashicorp.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Batch Token (&gt;= v1.10)</td>
<td><code>kingfisher.hashicorp.5</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Recovery Token (&gt;= v1.10)</td>
<td><code>kingfisher.hashicorp.6</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hashicorp</td>
<td>Hashicorp Vault Unseal Key</td>
<td><code>kingfisher.hashicorp.7</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hcaptcha</td>
<td>hCaptcha Site Verify Secret Key</td>
<td><code>kingfisher.hcaptcha.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Heartland</td>
<td>Heartland Portico API Key</td>
<td><code>kingfisher.heartland.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Helpscout</td>
<td>Help Scout Client ID</td>
<td><code>kingfisher.helpscout.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Helpscout</td>
<td>Help Scout OAuth Client Secret</td>
<td><code>kingfisher.helpscout.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hereapi</td>
<td>HERE API Key</td>
<td><code>kingfisher.hereapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Heroku</td>
<td>Heroku API Key</td>
<td><code>kingfisher.heroku.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Heroku</td>
<td>Heroku API Key (Platform Key)</td>
<td><code>kingfisher.heroku.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Hetzner</td>
<td>Hetzner Cloud API Token</td>
<td><code>kingfisher.hetzner.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hex</td>
<td>Hex Technologies API Token</td>
<td><code>kingfisher.hex.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hexpm</td>
<td>Hex.pm Organization Repository Key</td>
<td><code>kingfisher.hexpm.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Highnote</td>
<td>Highnote API Key</td>
<td><code>kingfisher.highnote.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Honeycomb</td>
<td>Honeycomb API Key</td>
<td><code>kingfisher.honeycomb.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hop</td>
<td>HOP Project Token</td>
<td><code>kingfisher.hop.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hop</td>
<td>HOP Personal Access Token</td>
<td><code>kingfisher.hop.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Http</td>
<td>HTTP Basic Authentication</td>
<td><code>kingfisher.http.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Http</td>
<td>HTTP Bearer Token</td>
<td><code>kingfisher.http.2</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Huawei</td>
<td>Huawei Open Platform Client ID</td>
<td><code>kingfisher.huawei.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Huawei</td>
<td>Huawei Open Platform Client Secret</td>
<td><code>kingfisher.huawei.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Hubspot</td>
<td>HubSpot Private App Token</td>
<td><code>kingfisher.hubspot.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Huggingface</td>
<td>HuggingFace User Access Token</td>
<td><code>kingfisher.huggingface.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Hunterio</td>
<td>Hunter.io API Key</td>
<td><code>kingfisher.hunterio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ibm</td>
<td>IBM Cloud User API Key</td>
<td><code>kingfisher.ibm.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Imagekit</td>
<td>ImageKit Private API Key</td>
<td><code>kingfisher.imagekit.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Infisical</td>
<td>Infisical Service Token</td>
<td><code>kingfisher.infisical.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Influxdb</td>
<td>InfluxDB API Token</td>
<td><code>kingfisher.influxdb.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Infracost</td>
<td>Infracost API Token</td>
<td><code>kingfisher.infracost.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Infura</td>
<td>Infura API Key</td>
<td><code>kingfisher.infura.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Inngest</td>
<td>Inngest Signing Key</td>
<td><code>kingfisher.inngest.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Inngest</td>
<td>Inngest Event Key</td>
<td><code>kingfisher.inngest.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Instagram</td>
<td>Instagram Graph API Access Token</td>
<td><code>kingfisher.instagram.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Instantly</td>
<td>Instantly API Key</td>
<td><code>kingfisher.instantly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Intercom</td>
<td>Intercom API Token</td>
<td><code>kingfisher.intercom.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Intra42</td>
<td>Intra42 Client ID</td>
<td><code>kingfisher.intra42.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Intra42</td>
<td>Intra42 Client Secret (s-s4t2ud/af)</td>
<td><code>kingfisher.intra42.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ionic</td>
<td>Ionic API token</td>
<td><code>kingfisher.ionic.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ipstack</td>
<td>IpStack API Key</td>
<td><code>kingfisher.ipstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Iterable</td>
<td>Iterable API Key</td>
<td><code>kingfisher.iterable.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Iterative</td>
<td>Iterative DVC Studio Access Token</td>
<td><code>kingfisher.iterative.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Jdbc</td>
<td>JDBC connection string with embedded credentials</td>
<td><code>kingfisher.jdbc.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jenkins</td>
<td>Jenkins Token or Crumb</td>
<td><code>kingfisher.jenkins.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Jfrog</td>
<td>JFrog Cloud Host</td>
<td><code>kingfisher.jfrog.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Jfrog</td>
<td>JFrog API Key</td>
<td><code>kingfisher.jfrog.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jfrog</td>
<td>JFrog Identity Token</td>
<td><code>kingfisher.jfrog.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jina</td>
<td>Jina Search Foundation API Key</td>
<td><code>kingfisher.jina.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jira</td>
<td>Jira Domain</td>
<td><code>kingfisher.jira.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Jira</td>
<td>Jira Token</td>
<td><code>kingfisher.jira.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jira</td>
<td>Jira Data Center Personal Access Token</td>
<td><code>kingfisher.jira.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Jira</td>
<td>Jira Data Center Domain</td>
<td><code>kingfisher.jira.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Jotform</td>
<td>Jotform API Key</td>
<td><code>kingfisher.jotform.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jumpcloud</td>
<td>Jumpcloud API Key</td>
<td><code>kingfisher.jumpcloud.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Jwt</td>
<td>JSON Web Token (base64url-encoded)</td>
<td><code>kingfisher.jwt.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kagi</td>
<td>Kagi API Key</td>
<td><code>kingfisher.kagi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kairos</td>
<td>Kairos API App ID</td>
<td><code>kingfisher.kairos.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Kairos</td>
<td>Kairos API Key</td>
<td><code>kingfisher.kairos.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Keenio</td>
<td>Keen.io API Key</td>
<td><code>kingfisher.keenio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Keenio</td>
<td>Keen.io Project ID</td>
<td><code>kingfisher.keenio.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Keycloak</td>
<td>Keycloak Client ID</td>
<td><code>kingfisher.keycloak.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Keycloak</td>
<td>Keycloak Client Secret</td>
<td><code>kingfisher.keycloak.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Kickbox</td>
<td>Kickbox API Key</td>
<td><code>kingfisher.kickbox.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Klaviyo</td>
<td>Klaviyo API Key</td>
<td><code>kingfisher.klaviyo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Klingai</td>
<td>Kling AI Secret Key</td>
<td><code>kingfisher.klingai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kraken</td>
<td>Kraken API Secret</td>
<td><code>kingfisher.kraken.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kraken</td>
<td>Kraken API Key</td>
<td><code>kingfisher.kraken.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Kubernetes</td>
<td>Kubernetes API Server URL</td>
<td><code>kingfisher.kubernetes.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Kubernetes</td>
<td>Kubernetes Bootstrap Token</td>
<td><code>kingfisher.kubernetes.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kubernetes</td>
<td>Kubernetes Bootstrap Token Pair</td>
<td><code>kingfisher.kubernetes.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kucoin</td>
<td>KuCoin API Key</td>
<td><code>kingfisher.kucoin.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Kucoin</td>
<td>KuCoin API Secret</td>
<td><code>kingfisher.kucoin.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Kucoin</td>
<td>KuCoin API Passphrase</td>
<td><code>kingfisher.kucoin.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Lacework</td>
<td>Lacework API Key ID</td>
<td><code>kingfisher.lacework.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Lacework</td>
<td>Lacework API Secret</td>
<td><code>kingfisher.lacework.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Langchain</td>
<td>LangSmith Personal Access Token</td>
<td><code>kingfisher.langchain.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Langchain</td>
<td>LangSmith Service Key</td>
<td><code>kingfisher.langchain.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Langfuse</td>
<td>Langfuse Secret Key</td>
<td><code>kingfisher.langfuse.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Langfuse</td>
<td>Langfuse Public Key</td>
<td><code>kingfisher.langfuse.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Laravel</td>
<td>Laravel Application Encryption Key</td>
<td><code>kingfisher.laravel.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Lark</td>
<td>LarkSuite Tenant Access Token</td>
<td><code>kingfisher.lark.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lark</td>
<td>LarkSuite User Access Token</td>
<td><code>kingfisher.lark.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lark</td>
<td>LarkSuite App Access Token</td>
<td><code>kingfisher.lark.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Launchdarkly</td>
<td>LaunchDarkly Access Token</td>
<td><code>kingfisher.launchdarkly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Ldap</td>
<td>LDAP Credentials</td>
<td><code>kingfisher.ldap.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ldap</td>
<td>LDAP Bind URI Credentials</td>
<td><code>kingfisher.ldap.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lemonsqueezy</td>
<td>LemonSqueezy API Key</td>
<td><code>kingfisher.lemonsqueezy.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lichess</td>
<td>Lichess Personal Access Token</td>
<td><code>kingfisher.lichess.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Line</td>
<td>Line Messaging API Token</td>
<td><code>kingfisher.line.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Linear</td>
<td>Linear API Key</td>
<td><code>kingfisher.linear.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Linkedin</td>
<td>LinkedIn Client ID</td>
<td><code>kingfisher.linkedin.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Linkedin</td>
<td>LinkedIn Secret Key</td>
<td><code>kingfisher.linkedin.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Linode</td>
<td>Linode Personal Access Token</td>
<td><code>kingfisher.linode.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Liveblocks</td>
<td>Liveblocks Secret Key</td>
<td><code>kingfisher.liveblocks.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Livekit</td>
<td>LiveKit API Key</td>
<td><code>kingfisher.livekit.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Livekit</td>
<td>LiveKit API Secret</td>
<td><code>kingfisher.livekit.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Livekit</td>
<td>LiveKit URL</td>
<td><code>kingfisher.livekit.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Llamacloud</td>
<td>Llama Cloud API Key</td>
<td><code>kingfisher.llamacloud.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lob</td>
<td>Lob API Key</td>
<td><code>kingfisher.lob.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Lob</td>
<td>Lob Publishable API Key</td>
<td><code>kingfisher.lob.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Localstack</td>
<td>LocalStack Simulated AWS Access Key</td>
<td><code>kingfisher.localstack.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Lokalise</td>
<td>Lokalise API Token</td>
<td><code>kingfisher.lokalise.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Looker</td>
<td>Looker Base URL</td>
<td><code>kingfisher.looker.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Looker</td>
<td>Looker Client ID</td>
<td><code>kingfisher.looker.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Looker</td>
<td>Looker Client Secret</td>
<td><code>kingfisher.looker.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Loops</td>
<td>Loops Email API Key</td>
<td><code>kingfisher.loops.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailchimp</td>
<td>Mailchimp API Key</td>
<td><code>kingfisher.mailchimp.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailersend</td>
<td>MailerSend API Token</td>
<td><code>kingfisher.mailersend.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailgun</td>
<td>MailGun Token</td>
<td><code>kingfisher.mailgun.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailgun</td>
<td>MailGun Primary Key</td>
<td><code>kingfisher.mailgun.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailjet</td>
<td>MailJetSMS API Key</td>
<td><code>kingfisher.mailjet.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mailjet</td>
<td>MailJet Basic Auth</td>
<td><code>kingfisher.mailjet.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mandrill</td>
<td>Mandrill API Key</td>
<td><code>kingfisher.mandrill.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mapbox</td>
<td>Mapbox Public Access Token</td>
<td><code>kingfisher.mapbox.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mapbox</td>
<td>Mapbox Secret Access Token</td>
<td><code>kingfisher.mapbox.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Mapbox</td>
<td>Mapbox Temporary Access Token</td>
<td><code>kingfisher.mapbox.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mappedin</td>
<td>Mappedin API Key</td>
<td><code>kingfisher.mappedin.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mappedin</td>
<td>Mappedin API Secret</td>
<td><code>kingfisher.mappedin.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mariadb</td>
<td>MariaDB Credentials</td>
<td><code>kingfisher.mariadb.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mastra</td>
<td>Mastra Memory Gateway API Key</td>
<td><code>kingfisher.mastra.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mattermost</td>
<td>Mattermost URL</td>
<td><code>kingfisher.mattermost.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mattermost</td>
<td>Mattermost Access Token</td>
<td><code>kingfisher.mattermost.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Maxmind</td>
<td>MaxMind License Key</td>
<td><code>kingfisher.maxmind.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Maxmind</td>
<td>MaxMind Account ID</td>
<td><code>kingfisher.maxmind.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mem0</td>
<td>Mem0 API Key</td>
<td><code>kingfisher.mem0.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mercadopago</td>
<td>Mercado Pago Access Token</td>
<td><code>kingfisher.mercadopago.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mercury</td>
<td>Mercury Production API Token</td>
<td><code>kingfisher.mercury.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mercury</td>
<td>Mercury Non-Production API Token</td>
<td><code>kingfisher.mercury.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mergify</td>
<td>Mergify Application API Key</td>
<td><code>kingfisher.mergify.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Messagebird</td>
<td>MessageBird API Token</td>
<td><code>kingfisher.messagebird.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Microsoft Teams</td>
<td>Microsoft Teams Webhook</td>
<td><code>kingfisher.msteams.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Microsoftteamswebhook</td>
<td>Microsoft Teams Webhook</td>
<td><code>kingfisher.microsoftteamswebhook.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Midtrans</td>
<td>Midtrans Sandbox Server/Client Key</td>
<td><code>kingfisher.midtrans.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Midtrans</td>
<td>Midtrans Production Server/Client Key</td>
<td><code>kingfisher.midtrans.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Minimax</td>
<td>MiniMax API Key</td>
<td><code>kingfisher.minimax.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mintlify</td>
<td>Mintlify API Key</td>
<td><code>kingfisher.mintlify.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Miro</td>
<td>Miro Access Token</td>
<td><code>kingfisher.miro.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Miro</td>
<td>Miro Client Secret</td>
<td><code>kingfisher.miro.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Miro</td>
<td>Miro Client ID</td>
<td><code>kingfisher.miro.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mistral</td>
<td>Mistral AI API Key</td>
<td><code>kingfisher.mistral.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mixpanel</td>
<td>Mixpanel API Secret</td>
<td><code>kingfisher.mixpanel.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mixpanel</td>
<td>Mixpanel Service Account Secret</td>
<td><code>kingfisher.mixpanel.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mixpanel</td>
<td>Mixpanel API Key or Secret</td>
<td><code>kingfisher.mixpanel.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mixpanel</td>
<td>Mixpanel Service Account Username</td>
<td><code>kingfisher.mixpanel.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Modal</td>
<td>Modal CLI Token Pair</td>
<td><code>kingfisher.modal.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Monday</td>
<td>Monday.com API Key</td>
<td><code>kingfisher.monday.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Moneywave</td>
<td>Moneywave / Flutterwave Private Key</td>
<td><code>kingfisher.moneywave.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mongodb</td>
<td>MongoDB API Private Key</td>
<td><code>kingfisher.mongodb.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Mongodb</td>
<td>MongoDB API PUBLIC Key</td>
<td><code>kingfisher.mongodb.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mongodb</td>
<td>MongoDB URI Connection String</td>
<td><code>kingfisher.mongodb.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mongodb</td>
<td>MongoDB Atlas Service Account Token</td>
<td><code>kingfisher.mongodb.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Moralis</td>
<td>Moralis API Key</td>
<td><code>kingfisher.moralis.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mssql</td>
<td>MSSQL Credentials</td>
<td><code>kingfisher.mssql.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mux</td>
<td>Mux Access Token Secret</td>
<td><code>kingfisher.mux.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Mux</td>
<td>Mux Access Token ID</td>
<td><code>kingfisher.mux.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Mysql</td>
<td>MySQL URI with Credentials</td>
<td><code>kingfisher.mysql.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nasa</td>
<td>NASA API Key</td>
<td><code>kingfisher.nasa.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Neo4J</td>
<td>Neo4j Database Credentials</td>
<td><code>kingfisher.neo4j.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Neon</td>
<td>Neon API Key</td>
<td><code>kingfisher.neon.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nessus</td>
<td>Nessus Agent Linking Key</td>
<td><code>kingfisher.nessus.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Netlify</td>
<td>Netlify API Key</td>
<td><code>kingfisher.netlify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Netlify</td>
<td>Netlify API Key</td>
<td><code>kingfisher.netlify.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Netlify</td>
<td>Netlify Personal Access Token (nfp_ prefix)</td>
<td><code>kingfisher.netlify.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Netrc</td>
<td>netrc Credentials</td>
<td><code>kingfisher.netrc.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Newrelic</td>
<td>New Relic Personal API Key</td>
<td><code>kingfisher.newrelic.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Newsapi</td>
<td>NewsAPI API Key</td>
<td><code>kingfisher.newsapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ngrok</td>
<td>Ngrok API Key</td>
<td><code>kingfisher.ngrok.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nightfall</td>
<td>Nightfall AI API Key</td>
<td><code>kingfisher.nightfall.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Notion</td>
<td>Notion Legacy Token</td>
<td><code>kingfisher.notion.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Notion</td>
<td>Notion Token</td>
<td><code>kingfisher.notion.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Notion</td>
<td>Notion OAuth Refresh Token</td>
<td><code>kingfisher.notion.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Npm</td>
<td>NPM Access Token (fine-grained)</td>
<td><code>kingfisher.npm.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Npm</td>
<td>NPM Access Token (old format)</td>
<td><code>kingfisher.npm.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Nuget</td>
<td>NuGet API Key</td>
<td><code>kingfisher.nuget.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nuget</td>
<td>NuGet API Key</td>
<td><code>kingfisher.nuget.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Numverify</td>
<td>Numverify API Key</td>
<td><code>kingfisher.numverify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nvidia</td>
<td>NVIDIA NIM API Key</td>
<td><code>kingfisher.nvidia.nim.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nxcloud</td>
<td>Nx Cloud Access Token</td>
<td><code>kingfisher.nxcloud.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nylas</td>
<td>Nylas API Key</td>
<td><code>kingfisher.nylas.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Nylas</td>
<td>Nylas API URI</td>
<td><code>kingfisher.nylas.api_uri.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Nytimes</td>
<td>New York Times API Key</td>
<td><code>kingfisher.nytimes.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Octopusdeploy</td>
<td>Octopus Deploy Server URL</td>
<td><code>kingfisher.octopusdeploy.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Octopusdeploy</td>
<td>Octopus Deploy API Key</td>
<td><code>kingfisher.octopusdeploy.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Odbc</td>
<td>Credentials in ODBC Connection String</td>
<td><code>kingfisher.odbc.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Okta</td>
<td>Okta API Token</td>
<td><code>kingfisher.okta.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Okta</td>
<td>Okta Domain</td>
<td><code>kingfisher.okta.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ollama</td>
<td>Ollama API Key</td>
<td><code>kingfisher.ollama.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Onelogin</td>
<td>OneLogin Client ID</td>
<td><code>kingfisher.onelogin.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Onelogin</td>
<td>OneLogin Client Secret</td>
<td><code>kingfisher.onelogin.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Onelogin</td>
<td>OneLogin Tenant Domain</td>
<td><code>kingfisher.onelogin.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Onepassword</td>
<td>1Password Service-Account Token</td>
<td><code>kingfisher.1password.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Onepassword</td>
<td>1Password Account Secret Key</td>
<td><code>kingfisher.1password.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Onesignal</td>
<td>OneSignal REST API Key</td>
<td><code>kingfisher.onesignal.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Onfido</td>
<td>Onfido API Token</td>
<td><code>kingfisher.onfido.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openai</td>
<td>OpenAI API Key</td>
<td><code>kingfisher.openai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openai</td>
<td>OpenAI API Key</td>
<td><code>kingfisher.openai.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openai</td>
<td>OpenAI API Key (Short Prefixed)</td>
<td><code>kingfisher.openai.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openrouter</td>
<td>OpenRouter API Key</td>
<td><code>kingfisher.openrouter.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openshift</td>
<td>OpenShift API Server URL</td>
<td><code>kingfisher.openshift.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Openshift</td>
<td>OpenShift OAuth Access Token</td>
<td><code>kingfisher.openshift.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Openvsx</td>
<td>OpenVSX Access Token</td>
<td><code>kingfisher.openvsx.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Openweathermap</td>
<td>OpenWeather Map API Key</td>
<td><code>kingfisher.openweather.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Opsgenie</td>
<td>OpsGenie API Key</td>
<td><code>kingfisher.opsgenie.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Optimizely</td>
<td>Optimizely Personal Access Token</td>
<td><code>kingfisher.optimizely.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Oracle</td>
<td>Oracle Database Connection URI</td>
<td><code>kingfisher.oracle.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ory</td>
<td>Ory API Key</td>
<td><code>kingfisher.ory.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ory</td>
<td>Ory Session Token</td>
<td><code>kingfisher.ory.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ory</td>
<td>Ory OAuth2 Token</td>
<td><code>kingfisher.ory.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ovh</td>
<td>OVH Application Key</td>
<td><code>kingfisher.ovh.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ovh</td>
<td>OVH Application Secret</td>
<td><code>kingfisher.ovh.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Owlbot</td>
<td>Owlbot API Key</td>
<td><code>kingfisher.owlbot.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Packagecloud</td>
<td>PackageCloud API Key</td>
<td><code>kingfisher.packagecloud.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Paddle</td>
<td>Paddle API Key</td>
<td><code>kingfisher.paddle.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pagerdutyapikey</td>
<td>PagerDuty API Key</td>
<td><code>kingfisher.pagerduty.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pandadoc</td>
<td>PandaDoc API Key</td>
<td><code>kingfisher.pandadoc.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pangea</td>
<td>Pangea Service Token</td>
<td><code>kingfisher.pangea.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Particle.Io</td>
<td>particle.io Access Token</td>
<td><code>kingfisher.particleio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Particle.Io</td>
<td>particle.io Access Token</td>
<td><code>kingfisher.particleio.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Pastebin</td>
<td>Pastebin API Key</td>
<td><code>kingfisher.pastebin.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Paypal</td>
<td>PayPal OAuth Client ID</td>
<td><code>kingfisher.paypal.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Paypal</td>
<td>PayPal OAuth Secret</td>
<td><code>kingfisher.paypal.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Paystack</td>
<td>Paystack API Key</td>
<td><code>kingfisher.paystack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pdflayer</td>
<td>PdfLayer API Key</td>
<td><code>kingfisher.pdflayer.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pem</td>
<td>PEM-Encoded Private Key</td>
<td><code>kingfisher.pem.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pem</td>
<td>Base64-PEM-Encoded Private Key</td>
<td><code>kingfisher.pem.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pendo</td>
<td>Pendo Integration Key</td>
<td><code>kingfisher.pendo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pepipost</td>
<td>Pepipost API Key</td>
<td><code>kingfisher.pepipost.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Permitio</td>
<td>Permit.io API Key</td>
<td><code>kingfisher.permitio.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Perplexity</td>
<td>Perplexity AI API Key</td>
<td><code>kingfisher.perplexity.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Persona</td>
<td>Persona API Key</td>
<td><code>kingfisher.persona.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Phpmailer</td>
<td>PHPMailer Credentials</td>
<td><code>kingfisher.phpmailer.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pinata</td>
<td>Pinata API Key ID</td>
<td><code>kingfisher.pinata.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pinata</td>
<td>Pinata API Secret</td>
<td><code>kingfisher.pinata.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pinata</td>
<td>Pinata JWT</td>
<td><code>kingfisher.pinata.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pinecone</td>
<td>Pinecone API Key</td>
<td><code>kingfisher.pinecone.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pingdom</td>
<td>Pingdom API Token</td>
<td><code>kingfisher.pingdom.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pingidentity</td>
<td>PingOne Client ID</td>
<td><code>kingfisher.pingidentity.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pingidentity</td>
<td>PingOne Client Secret</td>
<td><code>kingfisher.pingidentity.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pinterest</td>
<td>Pinterest Access Token</td>
<td><code>kingfisher.pinterest.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pinterest</td>
<td>Pinterest Refresh Token</td>
<td><code>kingfisher.pinterest.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pipedrive</td>
<td>Pipedrive API Token</td>
<td><code>kingfisher.pipedrive.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pirsch</td>
<td>Pirsch Analytics Access Key</td>
<td><code>kingfisher.pirsch.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Plaid</td>
<td>Plaid Client ID (helper)</td>
<td><code>kingfisher.plaid.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Plaid</td>
<td>Plaid Secret (Production)</td>
<td><code>kingfisher.plaid.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Plaid</td>
<td>Plaid Secret (Sandbox)</td>
<td><code>kingfisher.plaid.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Plaid</td>
<td>Plaid Access Token (Production)</td>
<td><code>kingfisher.plaid.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Plaid</td>
<td>Plaid Access Token (Sandbox)</td>
<td><code>kingfisher.plaid.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Planetscale</td>
<td>PlanetScale API Token</td>
<td><code>kingfisher.planetscale.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Planetscale</td>
<td>PlanetScale Username</td>
<td><code>kingfisher.planetscale.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Plivo</td>
<td>Plivo Auth ID</td>
<td><code>kingfisher.plivo.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Plivo</td>
<td>Plivo Auth Token</td>
<td><code>kingfisher.plivo.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Polar</td>
<td>Polar Personal Access Token</td>
<td><code>kingfisher.polar.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pollinations</td>
<td>Pollinations Secret Key</td>
<td><code>kingfisher.pollinations.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pollinations</td>
<td>Pollinations Publishable Key</td>
<td><code>kingfisher.pollinations.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Polymarket</td>
<td>Polymarket Builder Secret</td>
<td><code>kingfisher.polymarket.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Polymarket</td>
<td>Polymarket Builder Passphrase</td>
<td><code>kingfisher.polymarket.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Polymarket</td>
<td>Polymarket Builder API Key</td>
<td><code>kingfisher.polymarket.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Portainer</td>
<td>Portainer API Token</td>
<td><code>kingfisher.portainer.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Positionstack</td>
<td>Positionstack API Key</td>
<td><code>kingfisher.positionstack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Postgres</td>
<td>Postgres URL with hardcoded password</td>
<td><code>kingfisher.postgres.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Posthog</td>
<td>PostHog Personal API Key</td>
<td><code>kingfisher.posthog.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Posthog</td>
<td>PostHog Feature Flags Secure API Key</td>
<td><code>kingfisher.posthog.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Posthog</td>
<td>PostHog OAuth Access Token</td>
<td><code>kingfisher.posthog.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Posthog</td>
<td>PostHog OAuth Refresh Token</td>
<td><code>kingfisher.posthog.5</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Postman</td>
<td>Postman API Key</td>
<td><code>kingfisher.postman.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Postmark</td>
<td>Postmark API Token</td>
<td><code>kingfisher.postmark.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Prefect</td>
<td>Prefect API Token</td>
<td><code>kingfisher.prefect.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Privateai</td>
<td>Private AI API Key</td>
<td><code>kingfisher.privateai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Privkey</td>
<td>Contains encrypted RSA private key</td>
<td><code>kingfisher.privkey.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Privkey</td>
<td>Contains Private Key</td>
<td><code>kingfisher.privkey.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Proof</td>
<td>Proof API Key</td>
<td><code>kingfisher.proof.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Psexec</td>
<td>Credentials in PsExec</td>
<td><code>kingfisher.psexec.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pubnub</td>
<td>PubNub Publish Key</td>
<td><code>kingfisher.pubnub.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pubnub</td>
<td>PubNub Subscription Key</td>
<td><code>kingfisher.pubnub.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pulumi</td>
<td>Pulumi API Key</td>
<td><code>kingfisher.pulumi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pushbullet</td>
<td>Pushbullet Access Token</td>
<td><code>kingfisher.pushbullet.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Pusher</td>
<td>Pusher Channels App Key</td>
<td><code>kingfisher.pusher.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pusher</td>
<td>Pusher Channels App Secret</td>
<td><code>kingfisher.pusher.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Pypi</td>
<td>PyPI Upload Token</td>
<td><code>kingfisher.pypi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rabbitmq</td>
<td>RabbitMQ Credential</td>
<td><code>kingfisher.rabbitmq.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rails</td>
<td>Rails Master Key</td>
<td><code>kingfisher.rails.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Rails</td>
<td>Rails Secret Key Base</td>
<td><code>kingfisher.rails.2</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Railway</td>
<td>Railway API Token</td>
<td><code>kingfisher.railway.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rainforestpay</td>
<td>Rainforest Pay API Key</td>
<td><code>kingfisher.rainforestpay.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ramp</td>
<td>Ramp Client ID</td>
<td><code>kingfisher.ramp.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ramp</td>
<td>Ramp Client Secret</td>
<td><code>kingfisher.ramp.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rapidapi</td>
<td>RapidAPI Key</td>
<td><code>kingfisher.rapidapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Razorpay</td>
<td>Razorpay API Key</td>
<td><code>kingfisher.razorpay.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Razorpay</td>
<td>Razorpay Test API Key</td>
<td><code>kingfisher.razorpay.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Razorpay</td>
<td>Razorpay API Secret</td>
<td><code>kingfisher.razorpay.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>React</td>
<td>React App Username</td>
<td><code>kingfisher.reactapp.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>React</td>
<td>React App Password</td>
<td><code>kingfisher.reactapp.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Readme</td>
<td>ReadMe API Key</td>
<td><code>kingfisher.readme.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Recaptcha</td>
<td>reCAPTCHA API Key</td>
<td><code>kingfisher.recaptcha.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Redirectpizza</td>
<td>redirect.pizza API Token</td>
<td><code>kingfisher.redirectpizza.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Redis</td>
<td>Redis URI Connection String</td>
<td><code>kingfisher.redis.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Redis</td>
<td>Python Redis Client Debug Output</td>
<td><code>kingfisher.redis.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Redis</td>
<td>Redis Password (Standalone Config)</td>
<td><code>kingfisher.redis.3</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Redshift</td>
<td>Amazon Redshift Connection URI</td>
<td><code>kingfisher.redshift.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Render</td>
<td>Render API Key</td>
<td><code>kingfisher.render.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Replicate</td>
<td>Replicate API Token</td>
<td><code>kingfisher.replicate.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Resend</td>
<td>Resend API Key</td>
<td><code>kingfisher.resend.api_key.1</code></td>
<td>High</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Retellai</td>
<td>Retell AI API Key</td>
<td><code>kingfisher.retellai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ringcentral</td>
<td>RingCentral Client ID</td>
<td><code>kingfisher.ringcentral.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ringcentral</td>
<td>RingCentral Client Secret</td>
<td><code>kingfisher.ringcentral.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Ringcentral</td>
<td>RingCentral OAuth Base URL</td>
<td><code>kingfisher.ringcentral.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ringcentral</td>
<td>RingCentral Redirect URI</td>
<td><code>kingfisher.ringcentral.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Riot</td>
<td>Riot Platform Host</td>
<td><code>kingfisher.riot.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Riot</td>
<td>Riot Games API Key</td>
<td><code>kingfisher.riot.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Robinhood</td>
<td>Robinhood Crypto API Key</td>
<td><code>kingfisher.robinhood.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Rollbar</td>
<td>Rollbar Access Token</td>
<td><code>kingfisher.rollbar.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rootly</td>
<td>Rootly API Key</td>
<td><code>kingfisher.rootly.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Rubygems</td>
<td>RubyGems API Key</td>
<td><code>kingfisher.rubygems.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Runpod</td>
<td>RunPod API Key</td>
<td><code>kingfisher.runpod.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Runway</td>
<td>Runway API Key</td>
<td><code>kingfisher.runway.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Saladcloud</td>
<td>SaladCloud API Key</td>
<td><code>kingfisher.saladcloud.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Access Token</td>
<td><code>kingfisher.salesforce.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Instance URL</td>
<td><code>kingfisher.salesforce.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Consumer Key</td>
<td><code>kingfisher.salesforce.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Consumer Secret</td>
<td><code>kingfisher.salesforce.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Consumer Key and Secret</td>
<td><code>kingfisher.salesforce.5</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Refresh Token</td>
<td><code>kingfisher.salesforce.6</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Salesforce</td>
<td>Salesforce Connected App Consumer Key (Prefixed)</td>
<td><code>kingfisher.salesforce.7</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Salesloft</td>
<td>Salesloft API Key</td>
<td><code>kingfisher.salesloft.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Samsara</td>
<td>Samsara API Token (prefixed)</td>
<td><code>kingfisher.samsara.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Samsara</td>
<td>Samsara API Token (contextual)</td>
<td><code>kingfisher.samsara.2</code></td>
<td>Low</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sanity</td>
<td>Sanity API Token</td>
<td><code>kingfisher.sanity.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sauce</td>
<td>Sauce Labs Username</td>
<td><code>kingfisher.saucelabs.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sauce</td>
<td>Sauce Labs API Endpoint</td>
<td><code>kingfisher.saucelabs.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sauce</td>
<td>Sauce Labs Access Key</td>
<td><code>kingfisher.saucelabs.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Scale</td>
<td>Scale API Key</td>
<td><code>kingfisher.scale.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Scale</td>
<td>Scale Callback Auth Key</td>
<td><code>kingfisher.scale.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Scaleway</td>
<td>Scaleway Secret Key</td>
<td><code>kingfisher.scaleway.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Scalingo</td>
<td>Scalingo API Token</td>
<td><code>kingfisher.scalingo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Scalr</td>
<td>Scalr API Access Token</td>
<td><code>kingfisher.scalr.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Scraperapi</td>
<td>ScraperAPI Key</td>
<td><code>kingfisher.scraperapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Seam</td>
<td>Seam API Key</td>
<td><code>kingfisher.seam.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Segment</td>
<td>Segment Public API Token</td>
<td><code>kingfisher.segment.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Segment</td>
<td>Segment API Key</td>
<td><code>kingfisher.segment.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sendbird</td>
<td>Sendbird Application ID</td>
<td><code>kingfisher.sendbird.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sendbird</td>
<td>Sendbird API Token</td>
<td><code>kingfisher.sendbird.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sendgrid</td>
<td>Sendgrid API token</td>
<td><code>kingfisher.sendgrid.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Sendinblue</td>
<td>Sendinblue API Token</td>
<td><code>kingfisher.sendinblue.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sentry</td>
<td>Sentry Access Token</td>
<td><code>kingfisher.sentry.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sentry</td>
<td>Sentry Organization Token</td>
<td><code>kingfisher.sentry.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sentry</td>
<td>Sentry User Token</td>
<td><code>kingfisher.sentry.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Serpapi</td>
<td>SerpApi API Key</td>
<td><code>kingfisher.serpapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Settlemint</td>
<td>SettleMint Personal Access Token</td>
<td><code>kingfisher.settlemint.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Settlemint</td>
<td>SettleMint Application Access Token</td>
<td><code>kingfisher.settlemint.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Settlemint</td>
<td>SettleMint Service Access Token</td>
<td><code>kingfisher.settlemint.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Shippo</td>
<td>Shippo API Token</td>
<td><code>kingfisher.shippo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Shodan</td>
<td>SHODAN API Key</td>
<td><code>kingfisher.shodan.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Shopify</td>
<td>Shopify access token</td>
<td><code>kingfisher.shopify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Shopify</td>
<td>Shopify Domain</td>
<td><code>kingfisher.shopify.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Shortcut</td>
<td>Shortcut API Token</td>
<td><code>kingfisher.shortcut.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Shutterstock</td>
<td>Shutterstock OAuth Token</td>
<td><code>kingfisher.shutterstock.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sidekiq</td>
<td>Sidekiq Enterprise Credential</td>
<td><code>kingfisher.sidekiq.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sidekiq</td>
<td>Sidekiq Sensitive URL</td>
<td><code>kingfisher.sidekiq.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Signifyd</td>
<td>Signifyd API Key</td>
<td><code>kingfisher.signifyd.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Slack</td>
<td>Slack App Token</td>
<td><code>kingfisher.slack.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Slack</td>
<td>Slack Token</td>
<td><code>kingfisher.slack.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Slack</td>
<td>Slack Webhook</td>
<td><code>kingfisher.slack.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Smb</td>
<td>SMB / CIFS Connection URI</td>
<td><code>kingfisher.smb.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Smtp</td>
<td>SMTP Credentials</td>
<td><code>kingfisher.smtp.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Snowflake</td>
<td>Snowflake Connection URI Credentials</td>
<td><code>kingfisher.snowflake.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Snowflake</td>
<td>Snowflake Programmatic Access Token</td>
<td><code>kingfisher.snowflake.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Snowflake</td>
<td>Snowflake Account Host</td>
<td><code>kingfisher.snowflake.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Snyk</td>
<td>Snyk API Key</td>
<td><code>kingfisher.snyk.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Solr</td>
<td>Apache Solr Connection URI</td>
<td><code>kingfisher.solr.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sonarcloud</td>
<td>SonarCloud API Token</td>
<td><code>kingfisher.sonarcloud.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sonarqube</td>
<td>SonarQube API Key</td>
<td><code>kingfisher.sonarqube.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sonarqube</td>
<td>SonarQube Host</td>
<td><code>kingfisher.sonarqube.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sonarqube</td>
<td>SonarQube Token</td>
<td><code>kingfisher.sonarqube.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sourcegraph</td>
<td>Sourcegraph Access Token</td>
<td><code>kingfisher.sourcegraph.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sourcegraph</td>
<td>Sourcegraph _Legacy_ API Key</td>
<td><code>kingfisher.sourcegraph.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sourcegraph</td>
<td>Sourcegraph Cody Gateway Key</td>
<td><code>kingfisher.sourcegraph.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sparkpost</td>
<td>SparkPost API Key</td>
<td><code>kingfisher.sparkpost.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Splunk</td>
<td>Splunk Authentication Token</td>
<td><code>kingfisher.splunk.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Spotify</td>
<td>Spotify Access Token</td>
<td><code>kingfisher.spotify.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sqreen</td>
<td>Sqreen Token</td>
<td><code>kingfisher.sqreen.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Square</td>
<td>Square Access Token</td>
<td><code>kingfisher.square.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Square</td>
<td>Square Access Token</td>
<td><code>kingfisher.square.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Square</td>
<td>Square OAuth Secret</td>
<td><code>kingfisher.square.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Squarespace</td>
<td>Squarespace API Key</td>
<td><code>kingfisher.squarespace.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sshpass</td>
<td>SSH / SCP Password (sshpass)</td>
<td><code>kingfisher.sshpass.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sslmate</td>
<td>SslMate API Key</td>
<td><code>kingfisher.sslmate.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Stabilityai</td>
<td>Stability AI API Key</td>
<td><code>kingfisher.stabilityai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Stackhawk</td>
<td>StackHawk API Key</td>
<td><code>kingfisher.stackhawk.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Statsig</td>
<td>Statsig Server Secret Key</td>
<td><code>kingfisher.statsig.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Statuscake</td>
<td>StatusCake API Token</td>
<td><code>kingfisher.statuscake.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Statuspage</td>
<td>Statuspage API Key</td>
<td><code>kingfisher.statuspage.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Storyblok</td>
<td>Storyblok API Token</td>
<td><code>kingfisher.storyblok.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Strava</td>
<td>Strava Access Token</td>
<td><code>kingfisher.strava.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Stream</td>
<td>Stream.io API Key</td>
<td><code>kingfisher.stream.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Stream</td>
<td>Stream.io API Secret</td>
<td><code>kingfisher.stream.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Stripe</td>
<td>Stripe Publishable Key</td>
<td><code>kingfisher.stripe.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Stripe</td>
<td>Stripe Secret / Restricted Key</td>
<td><code>kingfisher.stripe.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Stytch</td>
<td>Stytch Project ID</td>
<td><code>kingfisher.stytch.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Stytch</td>
<td>Stytch Project Secret</td>
<td><code>kingfisher.stytch.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Sumologic</td>
<td>Sumo Logic Access ID</td>
<td><code>kingfisher.sumologic.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Sumologic</td>
<td>Sumo Logic Access Key</td>
<td><code>kingfisher.sumologic.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Supabase</td>
<td>Supabase Management Token</td>
<td><code>kingfisher.supabase.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Supabase</td>
<td>Supabase Project API Key</td>
<td><code>kingfisher.supabase.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Supabase</td>
<td>Supabase Project URL</td>
<td><code>kingfisher.supabase.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Supabase</td>
<td>Supabase Publishable Key</td>
<td><code>kingfisher.supabase.4</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Surge</td>
<td>Surge.sh Deploy Token</td>
<td><code>kingfisher.surge.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Svix</td>
<td>Svix Webhook Signing Secret</td>
<td><code>kingfisher.svix.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tableau</td>
<td>Tableau Personal Access Token</td>
<td><code>kingfisher.tableau.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Tableau</td>
<td>Tableau Server URL</td>
<td><code>kingfisher.tableau.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tableau</td>
<td>Tableau Site Content URL</td>
<td><code>kingfisher.tableau.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tailscale</td>
<td>Tailscale API Key</td>
<td><code>kingfisher.tailscale.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Tavily</td>
<td>Tavily API Key</td>
<td><code>kingfisher.tavily.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Tavus</td>
<td>Tavus API Key</td>
<td><code>kingfisher.tavus.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Teamcity</td>
<td>TeamCity API Token</td>
<td><code>kingfisher.teamcity.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Telegram</td>
<td>Telegram Bot Token</td>
<td><code>kingfisher.telegram.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Telnyx</td>
<td>Telnyx API V2 Key</td>
<td><code>kingfisher.telnyx.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Temporal</td>
<td>Temporal Cloud API Key</td>
<td><code>kingfisher.temporal.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Tencent</td>
<td>Tencent Cloud Secret ID</td>
<td><code>kingfisher.tencent.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tencent</td>
<td>Tencent Cloud Secret Key</td>
<td><code>kingfisher.tencent.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Terraform</td>
<td>Terraform Cloud / HCP Terraform API Token</td>
<td><code>kingfisher.terraform.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Testkube</td>
<td>Testkube API Key</td>
<td><code>kingfisher.testkube.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Testkube</td>
<td>Testkube Organization ID</td>
<td><code>kingfisher.testkube.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Testkube</td>
<td>Testkube Environment ID</td>
<td><code>kingfisher.testkube.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Thingsboard</td>
<td>ThingsBoard Access Token</td>
<td><code>kingfisher.thingsboard.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Thingsboard</td>
<td>ThingsBoard Provision Device Key</td>
<td><code>kingfisher.thingsboard.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Thingsboard</td>
<td>ThingsBoard Provision Device Secret</td>
<td><code>kingfisher.thingsboard.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Thunderstore</td>
<td>Thunderstore API Token</td>
<td><code>kingfisher.thunderstore.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Thycotic</td>
<td>Thycotic / Delinea Secret Server Credentials</td>
<td><code>kingfisher.thycotic.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tigris</td>
<td>Tigris Access Key ID</td>
<td><code>kingfisher.tigris.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tigris</td>
<td>Tigris Secret Access Key</td>
<td><code>kingfisher.tigris.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Tinybird</td>
<td>Tinybird Static Token</td>
<td><code>kingfisher.tinybird.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Todoist</td>
<td>Todoist API Token</td>
<td><code>kingfisher.todoist.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Togetherai</td>
<td>Together.ai API Key</td>
<td><code>kingfisher.together.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Tolgee</td>
<td>Tolgee Project API Key</td>
<td><code>kingfisher.tolgee.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Tolgee</td>
<td>Tolgee Personal Access Token</td>
<td><code>kingfisher.tolgee.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Travisci</td>
<td>Travis CI Token</td>
<td><code>kingfisher.travisci.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Travisci</td>
<td>Travis CI Encrypted Variable</td>
<td><code>kingfisher.travisci.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Trello</td>
<td>Trello API Token</td>
<td><code>kingfisher.trello.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Trello</td>
<td>Trello API Key</td>
<td><code>kingfisher.trello.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Trendmicro</td>
<td>Trend Micro Deep Security API Key</td>
<td><code>kingfisher.trendmicro.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Trendmicro</td>
<td>Trend Micro Cloud One API Key</td>
<td><code>kingfisher.trendmicro.2</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Triggerdev</td>
<td>Trigger.dev Secret Key</td>
<td><code>kingfisher.triggerdev.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Triggerdev</td>
<td>Trigger.dev Personal Access Token</td>
<td><code>kingfisher.triggerdev.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Triggerdev</td>
<td>Trigger.dev Project Reference</td>
<td><code>kingfisher.triggerdev.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Truenas</td>
<td>TrueNAS API Key (WebSocket)</td>
<td><code>kingfisher.truenas.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Truenas</td>
<td>TrueNAS API Key (REST API)</td>
<td><code>kingfisher.truenas.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Truenas</td>
<td>TrueNAS Instance URL</td>
<td><code>kingfisher.truenas.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Truenas</td>
<td>TrueNAS API Key (keyword proximity)</td>
<td><code>kingfisher.truenas.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Twilio</td>
<td>Twilio API ID</td>
<td><code>kingfisher.twilio.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Twilio</td>
<td>Twilio API Key</td>
<td><code>kingfisher.twilio.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Twitch</td>
<td>Twitch API Token</td>
<td><code>kingfisher.twitch.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Twitter</td>
<td>X / Twitter Bearer Token (App-only)</td>
<td><code>kingfisher.twitter.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Twitter</td>
<td>Twitter Consumer Key</td>
<td><code>kingfisher.twitter.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Twitter</td>
<td>X / Twitter Consumer Secret</td>
<td><code>kingfisher.twitter.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Typeform</td>
<td>Typeform API Token</td>
<td><code>kingfisher.typeform.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Uber</td>
<td>Uber Server Token</td>
<td><code>kingfisher.uber.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Ubidots</td>
<td>Ubidots API Key</td>
<td><code>kingfisher.ubidots.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Unkey</td>
<td>Unkey Root Key</td>
<td><code>kingfisher.unkey.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Unkey</td>
<td>Unkey API Key (key_ prefix)</td>
<td><code>kingfisher.unkey.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Unkey</td>
<td>Unkey API Key Secret (creation-only plaintext)</td>
<td><code>kingfisher.unkey.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Unleash</td>
<td>Unleash Client/Admin API Token</td>
<td><code>kingfisher.unleash.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Unleash</td>
<td>Unleash Personal Access Token</td>
<td><code>kingfisher.unleash.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Unsplash</td>
<td>Unsplash Access Key</td>
<td><code>kingfisher.unsplash.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Upcloud</td>
<td>UpCloud API Token</td>
<td><code>kingfisher.upcloud.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Upstash</td>
<td>Upstash Redis REST Token</td>
<td><code>kingfisher.upstash.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Upstash</td>
<td>Upstash Redis REST URL</td>
<td><code>kingfisher.upstash.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Upstash</td>
<td>Upstash Account Email</td>
<td><code>kingfisher.upstash.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Upstash</td>
<td>Upstash Management API Key</td>
<td><code>kingfisher.upstash.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Uptimerobot</td>
<td>UptimeRobot API Key</td>
<td><code>kingfisher.uptimerobot.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Uri</td>
<td>URI with Username and Secret</td>
<td><code>kingfisher.uri.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Urlscan</td>
<td>urlscan.io API Key</td>
<td><code>kingfisher.urlscan.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Valtown</td>
<td>Val Town API Token</td>
<td><code>kingfisher.valtown.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vapi</td>
<td>Vapi API Key</td>
<td><code>kingfisher.vapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vastai</td>
<td>Vast.ai API Key</td>
<td><code>kingfisher.vastai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel API Token (legacy 24-char)</td>
<td><code>kingfisher.vercel.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel Personal Access Token (vcp_)</td>
<td><code>kingfisher.vercel.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel Integration Token (vci_)</td>
<td><code>kingfisher.vercel.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel App Access Token (vca_)</td>
<td><code>kingfisher.vercel.4</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel App Refresh Token (vcr_)</td>
<td><code>kingfisher.vercel.5</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Vercel</td>
<td>Vercel AI Gateway API Key (vck_)</td>
<td><code>kingfisher.vercel.6</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Virustotal</td>
<td>VirusTotal API Key</td>
<td><code>kingfisher.virustotal.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vkontakte</td>
<td>VKontakte Access Token</td>
<td><code>kingfisher.vkontakte.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vmware</td>
<td>Credentials in Connect-VIServer Invocation</td>
<td><code>kingfisher.vmware.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Voiceflow</td>
<td>Voiceflow API Key</td>
<td><code>kingfisher.voiceflow.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Voiceflow</td>
<td>Voiceflow Project ID</td>
<td><code>kingfisher.voiceflow.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Volcengine</td>
<td>VolcEngine Access Key ID</td>
<td><code>kingfisher.volcengine.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Vonage</td>
<td>Vonage (Nexmo) API Key</td>
<td><code>kingfisher.vonage.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Vonage</td>
<td>Vonage (Nexmo) API Secret</td>
<td><code>kingfisher.vonage.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Voyageai</td>
<td>Voyage AI API Key</td>
<td><code>kingfisher.voyageai.api_key</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Voyageai</td>
<td>Voyage AI API Key</td>
<td><code>kingfisher.voyageai.api_key.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Vultr</td>
<td>Vultr API Key</td>
<td><code>kingfisher.vultr.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td>Yes</td>
</tr>
<tr>
<td>Wakatime</td>
<td>WakaTime API Key</td>
<td><code>kingfisher.wakatime.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wakatime</td>
<td>WakaTime Prefixed API Key</td>
<td><code>kingfisher.wakatime.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Warpstream</td>
<td>WarpStream API Key Secret</td>
<td><code>kingfisher.warpstream.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Weatherapi</td>
<td>WeatherAPI.com API Key</td>
<td><code>kingfisher.weatherapi.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Webex</td>
<td>Webex Integration Client ID</td>
<td><code>kingfisher.webex.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Webex</td>
<td>Webex Integration Client Secret</td>
<td><code>kingfisher.webex.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Webex</td>
<td>Webex Redirect URI</td>
<td><code>kingfisher.webex.3</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Webflow</td>
<td>Webflow API Token</td>
<td><code>kingfisher.webflow.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wechat</td>
<td>WeChat App ID</td>
<td><code>kingfisher.wechat.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Wechat</td>
<td>WeChat App Secret</td>
<td><code>kingfisher.wechat.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Weightsandbiases</td>
<td>Weights and Biases API Key</td>
<td><code>kingfisher.wandb.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Weightsandbiases</td>
<td>Weights and Biases API Key (v1)</td>
<td><code>kingfisher.wandb.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wepay</td>
<td>WePay Access Token</td>
<td><code>kingfisher.wepay.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wireguard</td>
<td>WireGuard Private Key</td>
<td><code>kingfisher.wireguard.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Wireguard</td>
<td>WireGuard Preshared Key</td>
<td><code>kingfisher.wireguard.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Wistia</td>
<td>Wistia API Token</td>
<td><code>kingfisher.wistia.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wiz</td>
<td>Wiz Client ID</td>
<td><code>kingfisher.wiz.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Wiz</td>
<td>Wiz Client Secret</td>
<td><code>kingfisher.wiz.2</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Woocommerce</td>
<td>WooCommerce Consumer Secret</td>
<td><code>kingfisher.woocommerce.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Woocommerce</td>
<td>WooCommerce Consumer Key</td>
<td><code>kingfisher.woocommerce.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Workato</td>
<td>Workato API Token</td>
<td><code>kingfisher.workato.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Workos</td>
<td>WorkOS API Key</td>
<td><code>kingfisher.workos.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wpengine</td>
<td>WPEngine API Key</td>
<td><code>kingfisher.wpengine.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Wpengine</td>
<td>WPEngine Account Name</td>
<td><code>kingfisher.wpengine.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Xai</td>
<td>xAI (Grok) API Key</td>
<td><code>kingfisher.xai.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Xata</td>
<td>Xata API Key</td>
<td><code>kingfisher.xata.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Xendit</td>
<td>Xendit API Key</td>
<td><code>kingfisher.xendit.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Yahoo</td>
<td>Yahoo OAuth2 Client ID</td>
<td><code>kingfisher.yahoo.1</code></td>
<td>High</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Yahoo</td>
<td>Yahoo OAuth2 Client Secret</td>
<td><code>kingfisher.yahoo.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Yandex</td>
<td>Yandex API Key</td>
<td><code>kingfisher.yandex.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Yelp</td>
<td>Yelp API Key</td>
<td><code>kingfisher.yelp.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Yousign</td>
<td>YouSign API Key</td>
<td><code>kingfisher.yousign.1</code></td>
<td>High</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Youtube</td>
<td>YouTube API Key</td>
<td><code>kingfisher.youtube.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zapier</td>
<td>Zapier Webhook URL</td>
<td><code>kingfisher.zapier.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Zendesk</td>
<td>Zendesk Subdomain</td>
<td><code>kingfisher.zendesk.1</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Zendesk</td>
<td>Zendesk Account Email</td>
<td><code>kingfisher.zendesk.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Zendesk</td>
<td>Zendesk API Token</td>
<td><code>kingfisher.zendesk.3</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zerobounce</td>
<td>ZeroBounce API Key</td>
<td><code>kingfisher.zerobounce.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zerotier</td>
<td>ZeroTier API Token</td>
<td><code>kingfisher.zerotier.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zhipu</td>
<td>Zhipu (BigModel) API Key</td>
<td><code>kingfisher.zhipu.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zohocrm</td>
<td>Zoho CRM API Access Token</td>
<td><code>kingfisher.zohocrm.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
<tr>
<td>Zoom</td>
<td>Zoom OAuth Client ID</td>
<td><code>kingfisher.zoom.1</code></td>
<td>Low</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Zoom</td>
<td>Zoom OAuth Client Secret</td>
<td><code>kingfisher.zoom.2</code></td>
<td>Medium</td>
<td></td>
<td></td>
</tr>
<tr>
<td>Zuplo</td>
<td>Zuplo API Key</td>
<td><code>kingfisher.zuplo.1</code></td>
<td>Medium</td>
<td>Yes</td>
<td></td>
</tr>
</tbody>
</table>
