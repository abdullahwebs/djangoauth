from django.shortcuts import render
from django.http import JsonResponse
import json
from .models import Register
import jwt
from django.utils.timezone import now, make_aware
from datetime import datetime, timedelta
from project.settings import SECRET_KEY
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password,check_password


# Token Creation and verificaion
def create_token(id):
     access_payload = {
         'user_id' : id,
         'exp': datetime.utcnow() + timedelta(minutes=15)
     }

     refresh_payload = {
         'user_id': id,
         'exp':  datetime.utcnow() + timedelta(days=7)
     }

     access_payload = jwt.encode(access_payload, SECRET_KEY, algorithm='HS256')
     refresh_payload = jwt.encode(refresh_payload, SECRET_KEY, algorithm='HS256')
  
     return access_payload,refresh_payload  

# Regnerate access token on expiry

def regnerate_token_view(request):
   try:
      token = request.COOKIES.get('refresh_token')
      decoded = jwt.decode(token, SECRET_KEY, algorithms='HS256')
      access_payload = {
           'user_id' : decoded['user_id'],
           'exp': datetime.utcnow() + timedelta(minutes=15)
       }
      response = JsonResponse({'status':True,'message':'token regenerated'})
      
      response.set_cookie(key='access_token', value=access_payload, httponly=True, secure=False)

      return response
   except Exception as e:
       return JsonResponse({'status':False,'message':str(e)}) 


# register view and token generation

@csrf_exempt
def register(request):
    try:
        if request.method != 'POST':
            return JsonResponse({"status": False, "message": "Invalid request method"}, status=405)

        data = json.loads(request.body)
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        phone = data.get('phone')

        # Check if user already exists
        if Register.objects.filter(email=email).exists():
            return JsonResponse({"status": False, "message": "User already exists"})

        # Hash password before storing it
        hashed_password = make_password(password)

        # Save user
        user = Register.objects.create(name=name, email=email, password=hashed_password, phone=phone)

        # Generate tokens
        refresh_token, access_token = create_token(user.id)

        # Prepare response
        response = JsonResponse({'status': True, 'message': 'User saved successfully'})
        response.set_cookie(key='access_token', value=access_token, httponly=True, secure=False)
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=False)

        return response

    except Exception as e:
        return JsonResponse({'status': False, 'message': f'Error: {str(e)}'})
    

# Login User

@csrf_exempt
def login(request):
    try:
        if request.method != 'POST':
            return JsonResponse({"status": False, "message": "Invalid request method"}, status=405)

        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        # Check user exists
        try:
            user = Register.objects.get(email=email)
        except Register.DoesNotExist:
            return JsonResponse({"status": False, "message": "User not found"}, status=404)

        # Check  password matches
        if check_password(password, user.password):  
            # Generate tokens
            refresh_token, access_token = create_token(user.id)
      
            response = JsonResponse({'status': True, 'message': 'User verified successfully'})
            response.set_cookie(key='access_token', value=access_token, httponly=True, secure=False)
            response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=False)

            return response

        return JsonResponse({"status": False, "message": "Incorrect password"}, status=401)

    except Exception as e:
        return JsonResponse({'status': False, 'message': f'Error: {str(e)}'}, status=500)






