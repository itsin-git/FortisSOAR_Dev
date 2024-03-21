import arrow
import base64
import json
from jose import jwt


# Taking logger as input, as the same method will be called from connector as well as server
# It will take the logger dynamically and accordingly log in server.log or connector.log file

def validate_token(token, input_id, logger):
    try:
        token_data_info = token.split('.')[1]
        decoded_token = json.loads(base64.b64decode(token_data_info + '=' * (-len(token_data_info) % 4)))
        auth_pub_key = decoded_token.get('pub_key')
        record_id = decoded_token.get('id')
        # Decoding token using public key from configurations
        claims = jwt.decode(token, key=auth_pub_key, algorithms=['RS512', 'RS256'])

        # Validating if token is not already expired
        if arrow.utcnow().timestamp() > claims.get('exp'):
            logger.error("token expired")
            return False

        if int(input_id) != int(record_id):
            logger.error("Input ID and token does not match")
            return False

        return True
    except Exception as e:
        logger.exception(e)
        return False
