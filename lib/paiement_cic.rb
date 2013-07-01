require 'digest/sha1'
require 'openssl'

class String

  def ^(other)
    raise ArgumentError, "Can't bitwise-XOR a String with a non-String" \
      unless other.kind_of? String
    raise ArgumentError, "Can't bitwise-XOR strings of different length" \
      unless self.length == other.length
    result = (0..self.length-1).collect { |i| self[i].ord ^ other[i].ord }
    result.pack("C*")
  end
end

class PaiementCic
  autoload :FormHelper, "paiement_cic/form_helper"

  @@version = "1.2open"
  cattr_accessor :version

  @@hmac_key = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" # clé extraite grâce à extract2HmacSha1.html fourni par le Crédit Mutuel
  cattr_accessor :hmac_key
  
  @@target_url = "https://paiement.creditmutuel.fr/paiement.cgi" # "https://ssl.paiement.cic-banques.fr/paiement.cgi"
  cattr_accessor :target_url
  
  @@tpe = "123456"
  cattr_accessor :tpe
  
  @@societe = "masociete"
  cattr_accessor :societe
  
  @@url_ok = ""
  cattr_accessor :url_ok

  def self.date_format
    "%d/%m/%Y:%H:%M:%S"
  end

  def self.config(amount_in_cents, reference)
    oa = ActiveSupport::OrderedHash.new
    oa["version"]     = "1.2open"
    oa["TPE"]         = tpe
    oa["date"]        = Time.now.strftime(date_format)
    oa["montant"]     =  ("%.2f" % amount_in_cents) + "EUR"
    oa["reference"]   = reference
    oa["texte-libre"] = ""
    oa["lgue"]      = "FR"
    oa["societe"]     = societe
    oa["mail"]        = ""
    oa
  end

  def self.mac_string params
    hmac_key = PaiementCic.new
    mac_string = [hmac_key.tpe, params["date"], params['montant'], params['reference'], params['texte-libre'], hmac_key.version, params['code-retour'], params['cvx'], params['vld'], params['brand'], params['status3ds'], params['numauto'], params['motifrefus'], params['originecb'], params['bincb'], params['hpancb'], params['ipclient'], params['originetr'], params['veres'], params['pares']].join('*') + "*"
  end

  def self.verify_hmac params
    hmac_key = PaiementCic.new
    mac_string = params['retourPLUS'] + [hmac_key.tpe, params["date"], params['montant'], params['reference'], params['texte-libre'], hmac_key.version, params['code-retour'], ''].join('+')

    hmac_key.valid_hmac?(mac_string, params['MAC'])
  end
	
  # Check if the HMAC matches the HMAC of the data string
	def valid_hmac?(mac_string, sent_mac)
		computeHMACSHA1(mac_string) == sent_mac.downcase
	end
	
  # Return the HMAC for a data string
	def computeHMACSHA1(data)
		hmac(data)
	end
	
	def hmac(data)
    pass = "QQcU6ekIBjJSpis6wPIv";
    k1 = [Digest::SHA1.hexdigest(pass)].pack("H*");
    l1 = k1.length

    k2 = [self.hmac_key].pack("H*")
    l2 = k2.length
    if (l1 > l2)
      k2 = k2.ljust(l1, 0.chr)
    elsif (l2 > l1)
      k1 = k1.ljust(l2, 0.chr)
    end
    xor_res = k1 ^ k2
    hmac_sha1(xor_res, data).downcase	
	end
	
  def hmac_sha1(key, data)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("sha1"), key, data)
  end

end
