#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError


from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(
            username = json.get('username'),
            image_url = json.get('image_url'),
            bio = json.get('bio')
        )
        if not json.get('username'):
            return {'error': 'Username is required'}, 422

        user.password_hash = json['password']
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'error': 'username exists'}
        session['user_id'] = user.id
        if user:
            return make_response(
                ({
                    'id': user.id,
                    'username':user.username,
                    'image_url':user.image_url,
                    'bio':user.bio
                }, 201)
            )
        return ({'error': 'user invalid'}), 422

class CheckSession(Resource):
    def get(self):
        user_id  = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return ({
                        'id': user.id,
                        'username':user.username,
                        'image_url': user.image_url,
                        'bio':user.bio
                    }),200
                
            
        return ({'error':'Unauthorized'}), 401
        

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        if not json_data:
            return {'error': 'No data provided'}, 400  

        username = json_data.get('username')
        password = json_data.get('password')

        if not username or not password:
            return {'error': 'Username and password are required'}, 422  
        user = User.query.filter(User.username == username).first()

        
        if user is None:
            return {'error': 'Invalid username or password'}, 401 

        
        if user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200  

        
        return {'error': 'Invalid username or password'}, 401  

class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id'] is not None:
            session.pop('user_id', None)
            return '', 204
        else:
            return ({'error':'Unauthorized'}), 401


class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {'error': 'Unauthorized'}, 401  # Ensure this line is reached when not logged in

        
        recipes = Recipe.query.all()
        recipes_data = [
            {
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username
                }
            } for recipe in recipes
        ]
        return recipes_data, 200

    def post(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {'error': 'Unauthorized'}, 401

        json = request.get_json()
        title = json.get('title')
        instructions = json.get('instructions')
        minutes_to_complete = json.get('minutes_to_complete')

        if not title or not instructions or not minutes_to_complete:
            return {'error': 'Invalid recipe data'}, 422
        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )
            db.session.add(recipe)
            db.session.commit()
            return {
            'id': recipe.id,
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user_id': recipe.user_id  # You can include user ID if needed
        }, 201 
        except ValueError as e:
            return {'error': str(e)},422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)