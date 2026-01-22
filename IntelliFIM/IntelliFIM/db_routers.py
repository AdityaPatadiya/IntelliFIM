"""
Database routers for separating accounts and FIM databases
"""

class AuthFIMRouter:
    """
    A router to control all database operations:
    - accounts, auth, contenttypes, admin → auth_db
    - fim, celery, sessions, etc. → default (fim_dev)
    """
    
    # Apps that should go to auth_db
    auth_db_apps = [
        'accounts',
        'auth',
        'contenttypes',
        'admin',
    ]

    def db_for_read(self, model, **hints):
        """Send auth-related apps to auth_db, everything else to default."""
        if model._meta.app_label in self.auth_db_apps:
            return 'auth_db'
        return 'default'

    def db_for_write(self, model, **hints):
        """Send auth-related apps to auth_db, everything else to default."""
        if model._meta.app_label in self.auth_db_apps:
            return 'auth_db'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if both objects are in the same database.
        """
        db_set = {'auth_db', 'default'}

        # Both objects are in auth_db
        if obj1._state.db in db_set and obj2._state.db in db_set:
            return True

        # Allow relations between objects in the same database
        return obj1._state.db == obj2._state.db

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure auth-related apps only appear in 'auth_db' database.
        All other apps go to 'default' database.
        """
        if app_label in self.auth_db_apps:
            return db == 'auth_db'
        return db == 'default'
