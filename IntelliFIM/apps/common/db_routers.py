class FIMRouter:
    """
    A router to contol all database operations on FIM models
    """
    fim_apps = {'fim'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.fim_apps:
            return 'fim_db'
        return None
    
    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.fim_apps:
            return 'fim_Db'
        return None
    
    def allow_relation(self, obj1, obj2, **hints):
        if (obj1._meta.app_label in self.fim_apps or
            obj2._meta.app_label in self.fim_apps):
            return True
        return None
    
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.fim_apps:
            return db == 'fim_db'
        return db == 'default'
