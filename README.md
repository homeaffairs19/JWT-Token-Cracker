# JWT-Token-Cracker

pip install -r requirements.txt

pip install PyJWT pytest

#for dictionary attack
python jwt_cracker.py --token <JWT_TOKEN> --dictionary <PATH_TO_DICTIONARY_FILE> --alg <ALGORITHM>

#for brute force
python jwt_cracker.py --token <JWT_TOKEN> --alphabet abc --max 3 --alg <ALGORITHM>

