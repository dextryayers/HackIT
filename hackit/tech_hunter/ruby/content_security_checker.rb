#!/usr/bin/env ruby
require 'json'

begin
  headers_json = ARGV[0] || '{}'
  headers = JSON.parse(headers_json) rescue nil
  headers = {} unless headers.is_a?(Hash)

  normalized = {}
  headers.each { |k, v| normalized[k.downcase] = v.to_s }

  checks = []
  critical = 0
  warnings = 0

  csp = normalized['content-security-policy']
  if csp && !csp.empty?
    checks << { header: 'Content-Security-Policy', status: 'OK', value: csp }
  else
    checks << { header: 'Content-Security-Policy', status: 'WARN', detail: 'Missing CSP header' }
    warnings += 1
  end

  hsts = normalized['strict-transport-security']
  if hsts && !hsts.empty?
    if hsts =~ /max-age=(\d+)/
      max_age = $1.to_i
      if max_age >= 31536000
        checks << { header: 'Strict-Transport-Security', status: 'OK', value: hsts }
      else
        checks << { header: 'Strict-Transport-Security', status: 'WARN', detail: "max-age=#{max_age} is less than 1 year" }
        warnings += 1
      end
    else
      checks << { header: 'Strict-Transport-Security', status: 'OK', value: hsts }
    end
  else
    checks << { header: 'Strict-Transport-Security', status: 'WARN', detail: 'Missing HSTS header' }
    warnings += 1
  end

  xfo = normalized['x-frame-options']
  if xfo
    if xfo.upcase == 'DENY' || xfo.upcase == 'SAMEORIGIN'
      checks << { header: 'X-Frame-Options', status: 'OK', value: xfo }
    else
      checks << { header: 'X-Frame-Options', status: 'WARN', detail: "Unexpected value: #{xfo}" }
      warnings += 1
    end
  else
    checks << { header: 'X-Frame-Options', status: 'WARN', detail: 'Missing X-Frame-Options header' }
    warnings += 1
  end

  xcto = normalized['x-content-type-options']
  if xcto && xcto.downcase == 'nosniff'
    checks << { header: 'X-Content-Type-Options', status: 'OK', value: xcto }
  elsif xcto
    checks << { header: 'X-Content-Type-Options', status: 'WARN', detail: "Unexpected value: #{xcto}" }
    warnings += 1
  else
    checks << { header: 'X-Content-Type-Options', status: 'WARN', detail: 'Missing X-Content-Type-Options header' }
    warnings += 1
  end

  rp = normalized['referrer-policy']
  if rp && !rp.empty?
    strict_vals = %w[no-referrer strict-origin-when-cross-origin same-origin]
    unsafe_vals = %w[unsafe-url no-referrer-when-downgrade origin-when-cross-origin]
    if strict_vals.any? { |v| rp.downcase.include?(v) }
      checks << { header: 'Referrer-Policy', status: 'OK', value: rp }
    elsif unsafe_vals.any? { |v| rp.downcase.include?(v) }
      checks << { header: 'Referrer-Policy', status: 'WARN', detail: "Permissive policy: #{rp}" }
      warnings += 1
    else
      checks << { header: 'Referrer-Policy', status: 'INFO', value: rp }
    end
  else
    checks << { header: 'Referrer-Policy', status: 'INFO', detail: 'Missing Referrer-Policy header' }
  end

  pp = normalized['permissions-policy'] || normalized['feature-policy']
  if pp && !pp.empty?
    checks << { header: 'Permissions-Policy', status: 'OK', value: pp }
  else
    checks << { header: 'Permissions-Policy', status: 'INFO', detail: 'Missing Permissions-Policy header' }
  end

  acao = normalized['access-control-allow-origin']
  if acao
    if acao == '*'
      checks << { header: 'Access-Control-Allow-Origin', status: 'WARN', detail: 'Wildcard CORS origin' }
      warnings += 1
    else
      checks << { header: 'Access-Control-Allow-Origin', status: 'OK', value: acao }
    end
  end

  cookie_checks = []
  set_cookie = normalized['set-cookie']
  if set_cookie && !set_cookie.empty?
    cookie_checks << 'Secure flag missing' unless set_cookie.downcase.include?('secure')
    cookie_checks << 'HttpOnly flag missing' unless set_cookie.downcase.include?('httponly')
    cookie_checks << 'SameSite flag missing' unless set_cookie.downcase.include?('samesite')
    unless cookie_checks.empty?
      checks << { header: 'Set-Cookie', status: 'WARN', detail: cookie_checks.join(', ') }
      warnings += cookie_checks.size
    end
  end

  total_checks = [csp, hsts, xfo, xcto, rp, pp, acao].compact.size
  max_checks = 7
  score = ((total_checks.to_f / max_checks) * 100).round
  score -= (warnings * 5)
  score = [[score, 0].max, 100].min

  grade = if score >= 90 then 'A'
           elsif score >= 75 then 'B'
           elsif score >= 50 then 'C'
           elsif score >= 25 then 'D'
           else 'F'
           end

  result = {
    checks: checks,
    score: score,
    grade: grade,
    critical_issues: critical,
    warnings: warnings
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
