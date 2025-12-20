"""
Database routers for separating auth and FIM databases
"""

class AuthFIMRouter:
    """
    A router to control all database operations on models in the
    auth and FIM applications.
    """
    
    def db_for_read(self, model, **hints):
        """
        Attempts to read auth models go to auth_db, FIM models go to default.
        """
        if model._meta.app_label == 'accounts':
            return 'auth_db'
        elif model._meta.app_label == 'fim':
            return 'default'
        return None
    
    def db_for_write(self, model, **hints):
        """
        Attempts to write auth models go to auth_db, FIM models go to default.
        """
        if model._meta.app_label == 'accounts':
            return 'auth_db'
        elif model._meta.app_label == 'fim':
            return 'default'
        return None
    
    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if both models are in the same database.
        """
        db_set = {'auth_db', 'default'}
        if obj1._state.db in db_set and obj2._state.db in db_set:
            return obj1._state.db == obj2._state.db
        return None
    
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the auth app only appears in the 'auth_db' database
        and FIM app only appears in the 'default' database.
        """
        if app_label == 'accounts':
            return db == 'auth_db'
        elif app_label == 'fim':
            return db == 'default'
        return None
