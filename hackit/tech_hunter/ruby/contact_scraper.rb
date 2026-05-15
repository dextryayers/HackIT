require 'json'

def extract_contacts(body, headers)
  # Advanced Regex for Email and Phone extraction
  email_regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
  phone_regex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}?\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/

  emails = body.scan(email_regex).uniq
  phones = body.scan(phone_regex).uniq.select { |p| p.length > 8 } # Filter short noise

  {
    "scraped_emails" => emails,
    "scraped_phones" => phones
  }
end

if __FILE__ == $0
  body = ARGV[0] || ""
  headers = ARGV[1] || ""
  puts JSON.generate(extract_contacts(body, headers))
end
