-- Deep Response Body Analyzer
local body = arg[1] or ""

local patterns = {
    {pat = "csrf",           cat = "CSRF Token",     risk = "low"},
    {pat = "csrf_token",     cat = "CSRF Token",     risk = "low"},
    {pat = "nonce",          cat = "Nonce Token",    risk = "low"},
    {pat = "authenticity_token", cat = "Auth Token", risk = "low"},
    {pat = "__VIEWSTATE",    cat = "ASP.NET ViewState", risk = "medium"},
    {pat = "jsessionid",     cat = "JSESSIONID",     risk = "medium"},
    {pat = "PHPSESSID",      cat = "PHP Session",    risk = "medium"},
    {pat = "aws",            cat = "AWS Reference",  risk = "low"},
    {pat = "s3%.amazonaws",  cat = "S3 Bucket URL",  risk = "high"},
    {pat = "firebaseio",     cat = "Firebase DB",    risk = "high"},
    {pat = "microsoft",      cat = "Azure Ref",      risk = "low"},
    {pat = "googleapis",     cat = "Google API",     risk = "low"},
    {pat = "stripe",         cat = "Stripe Ref",     risk = "medium"},
    {pat = "paypal",         cat = "PayPal Ref",     risk = "medium"},
    {pat = "github",         cat = "GitHub Ref",     risk = "low"},
    {pat = "gitlab",         cat = "GitLab Ref",     risk = "low"},
    {pat = "bitbucket",      cat = "Bitbucket Ref",  risk = "low"},
    {pat = "docker",         cat = "Docker Ref",     risk = "low"},
    {pat = "jira",           cat = "Jira Ref",       risk = "low"},
    {pat = "confluence",     cat = "Confluence Ref", risk = "low"},
    {pat = "jenkins",        cat = "Jenkins Ref",    risk = "medium"},
    {pat = "slack",          cat = "Slack Ref",      risk = "medium"},
    {pat = "discord",        cat = "Discord Ref",    risk = "medium"},
    {pat = "api[keyK]ey",    cat = "API Key Pattern", risk = "high"},
    {pat = "secret",         cat = "Secret Pattern", risk = "high"},
    {pat = "password",       cat = "Password Pattern", risk = "high"},
    {pat = "token",          cat = "Token Pattern",  risk = "medium"},
    {pat = "jwt",            cat = "JWT Reference",  risk = "medium"},
    {pat = "bearer",         cat = "Bearer Token",   risk = "high"},
    {pat = "oauth",          cat = "OAuth Ref",      risk = "medium"},
    {pat = "localhost",      cat = "Localhost Ref",  risk = "low"},
    {pat = "127%.0%.0%.1",   cat = "Loopback Ref",   risk = "low"},
    {pat = "10%.",           cat = "Private IP Range", risk = "medium"},
    {pat = "172%.1[6-9]",    cat = "Private IP Range", risk = "medium"},
    {pat = "192%.168%.",     cat = "Private IP Range", risk = "medium"},
    {pat = "internal",       cat = "Internal Ref",   risk = "medium"},
    {pat = "debug",          cat = "Debug Ref",      risk = "high"},
    {pat = "error",          cat = "Error Message",  risk = "low"},
    {pat = "stacktrace",     cat = "Stack Trace",    risk = "high"},
    {pat = "exception",      cat = "Exception Ref",  risk = "medium"},
}

local body_lower = string.lower(body)
local findings = {}

for _, p in ipairs(patterns) do
    local found = string.find(body_lower, p.pat)
    if found then
        table.insert(findings, string.format("%s|%s|%s", p.cat, p.risk, p.pat))
    end
end

if #findings > 0 then
    print(table.concat(findings, "\n"))
else
    print("NO_FINDINGS")
end
