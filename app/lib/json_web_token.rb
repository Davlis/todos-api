class JsonWebToken

  HMAC_SECRET = Rails.application.secrets.secret_key_base

  def self.encode(payload, exp = 24.hours.from_now)
    payload[:exp] = exp.to_i
    JWT.encode(payload, HMAC_SECRET)
  end

  def self.decode(token)
    body = JWT.decode(token, HMAC_SECRET)[0]
    HashWithIndifferentAccess.new body
    # rescue from expiry exception
  rescue JWT::ExpiredSignature, JWT::VerificationError => e
    # raise custom error to be handled by custom handler
    raise ExceptionHandler::ExpiredSignature, e.message
  end
end