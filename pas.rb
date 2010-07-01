require 'net/http'
require 'net/https'
require 'base64'
require 'cgi'
require 'openssl'
require 'rexml/document'

class Pas
  DIGEST = OpenSSL::Digest::Digest.new('sha1')

  API_ACCESS_KEY = "change_this"
  API_TOKEN = "please_change_me"

  def gen_timestamp
    Time.now.strftime("%y%m%d%H%M%S")
  end

  def hmac(key, text)
    digest = OpenSSL::HMAC.digest(DIGEST, key, text)
    return Base64.encode64(digest).chomp
  end

  def create_sig(api_access_key, api_token, http_method, uri, timestamp)
    cstring = api_token + http_method + uri + timestamp
    sig = hmac(api_access_key, cstring)
    final_sig = CGI.escape(sig)
  end

  def test_sig
    real_sig = "3gc17tMRqcXHxFKxBEdheCYfb0Q%3D"
    our_sig = create_sig('BaEc8f13QlXgjQd4fBQ', '143aec8f13dfcc6cb364e6a9c9ff4bb0', 'GET', '/publisher_members/404043.xml','1276980199')
  
    if real_sig.eql? our_sig then
      puts "passing tests!!"
    else
      puts "big fucking fail whale!"
    end
  end

  def authtoken(memberid)
    uri = "/remote_auth.xml"
    timestamp = gen_timestamp

    sig = create_sig(API_ACCESS_KEY, API_TOKEN, 'POST', uri, timestamp)
    path = uri+"?"+"api_token=#{API_TOKEN}&timestamp=#{timestamp}&signature=#{sig}"

    http = Net::HTTP.new("publisher.pokeraffiliatesolutions.com", 443)
    http.use_ssl = true
    data = "<member_id>#{memberid}</member_id>"
    headers = { 'Content-Type' => 'text/xml' }

    resp, xml = http.post(path, data, headers)

    doc = REXML::Document.new xml
    token = REXML::XPath.first(doc, "remote_auth_token/")

    if token.nil? then
      Raise NoToken
    else
      token.text
    end
  end

  def memberlist
    uri = "/publisher_members.xml"
    timestamp = gen_timestamp

    sig = create_sig(API_ACCESS_KEY, API_TOKEN, 'GET', uri, timestamp)
    url = "http://publisher.pokeraffiliatesolutions.com"+uri+"?"+"api_token=#{API_TOKEN}&timestamp=#{timestamp}&signature=#{sig}"
    xml = Net::HTTP.get_print URI.parse(url)
  end

  def show_member(memberid)
    uri = "/publisher_members/#{memberid}.xml"
    timestamp = gen_timestamp

    sig = create_sig(API_ACCESS_KEY, API_TOKEN, 'GET', uri, timestamp)
    url = "http://publisher.pokeraffiliatesolutions.com"+uri
    params = "?"+"api_token=#{API_TOKEN}&timestamp=#{timestamp}&signature=#{sig}"
    http = Net::HTTP.new(URI.parse(url).host,443)
    req = Net::HTTP::Get.new(URI.parse(url).path + params)
    http.use_ssl = true
    response = http.request(req) 
    return response.body
  end

end
