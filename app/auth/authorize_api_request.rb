class AuthorizeApiRequest
  def initialize(headers = {})
    @headers = headers
  end

  def call
    {
      user: user
    }
  end

  private

  attr_reader :headers

  def user
    # check if user is in the database
    # memorize user object
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    # handle user not found

  rescue ActiveRecord::RecordNotFound => e 
    #raise custom error
    raise(
      ExceptionlHandler::InvalidToken,
      ("#{Message.invalid_token} #{e.message}")
    )

  end

  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
  end

  def http_auth_header
    if headers['Authorization'].present?
      return headers['Authorization'].split(' ').last
    end
      raise(ExceptionlHandler::MissingToken, Message.missing_token)

end