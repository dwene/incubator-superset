import json

from flask import request
from flask_appbuilder import expose
from superset import appbuilder, db, security_manager, csrf
from .base import BaseSupersetView
from ..models.core import Database


class Clipwise(BaseSupersetView):
    """The base views for Superset!"""

    # {project_name, database_uri}
    @csrf.exempt
    @expose("/database/add", methods=["POST"])
    def setup_database(self):
        self.verify_super_admin(request)
        database_data = request.get_json()
        uri = database_data['uri']
        project_name = database_data['project_name']
        database = self.add_database(uri, project_name)
        permission_view = security_manager.add_permission_view_menu("database_access", database.perm)
        # adding a new database we always want to force refresh schema list
        for schema in database.get_all_schema_names():
            security_manager.add_permission_view_menu(
                "schema_access", security_manager.get_schema_perm(db, schema)
            )
        role = security_manager.add_role(project_name)
        security_manager.add_permission_role(role, permission_view)
        return self.json_response({"message": "Done"})

    # {first_name, last_name, email, password, is_coach}
    @csrf.exempt
    @expose("/user/add", methods=["POST"])
    def save(self):
        self.verify_super_admin(request)
        data = request.get_json()
        user = security_manager.find_user(data['email'])
        is_coach = data['is_coach']
        if user is None:
            user = self.add_user(data)
        sql_lab_role = security_manager.find_role('sql_lab')
        project_role = security_manager.find_role(data['project_name'])
        gamma_role = security_manager.find_role('Gamma')
        if gamma_role not in user.roles:
            user.roles.append(gamma_role)
        if sql_lab_role not in user.roles:
            user.roles.append(sql_lab_role)
        if project_role not in user.roles and is_coach:
            user.roles.append(project_role)
        if not is_coach:
            user.roles.remove(project_role)

        security_manager.update_user(user)
        return self.json_response({"message": "Done"})

    @staticmethod
    def add_user(data):
        return security_manager.add_user(data['email'], data['first_name'], data['last_name'], data['email'],
                                         security_manager.find_role("Gamma"), data['password'])

    @staticmethod
    def add_database(uri, name):
        database = Database()
        database.set_sqlalchemy_uri(uri)
        database.database_name = name
        db.session.add(database)
        db.session.commit()
        return database

    @staticmethod
    def verify_super_admin(request):
        if request.headers.get('Authorization') == "SUPER_ADMIN":
            return
        raise Exception("You do not have permissions to use this resource")


appbuilder.add_view_no_menu(Clipwise)