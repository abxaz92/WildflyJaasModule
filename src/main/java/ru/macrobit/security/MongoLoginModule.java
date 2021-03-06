package ru.macrobit.security;

import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.bson.types.ObjectId;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import com.mongodb.BasicDBObjectBuilder;
import com.mongodb.DB;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;

public class MongoLoginModule extends UsernamePasswordLoginModule {
    private static final Logger LOG = Logger.getLogger("LoginModule");
    private List<ObjectId> userGroup;
    private String database;
    private String username;
    private String password;

    private static final String DATABASE = "database";
    private static final String USERNAME = "username";
    private static final String PASSWD = "password";

    private static final String[] ALL_VALID_OPTIONS = {DATABASE, USERNAME,
            PASSWD};

    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        addValidOptions(ALL_VALID_OPTIONS);
        super.initialize(subject, callbackHandler, sharedState, options);
        database = (String) options.get("database");
        username = (String) options.get("username");
        password = (String) options.get("password");
    }

    /**
     * (required) The UsernamePasswordLoginModule modules compares the result of
     * this method with the actual password.
     */
    @Override
    protected String getUsersPassword() throws LoginException {
        String password = super.getUsername();
        password = password.toUpperCase();
        return password;
    }

    /**
     * (optional) Override if you want to change how the password are compared
     * or if you need to perform some conversion on them.
     */
    @Override
    protected boolean validatePassword(String inputPassword,
                                       String expectedPassword) {
        try {
            LOG.info(expectedPassword + " " + inputPassword);
            if (inputPassword.equals(doFindUser())) {
                LOG.info(expectedPassword + " success authentificated!!!");
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private static final String SERVIER_ADDR = "db";
    private static final String PERMISSIONS = "permissions";

    @Override
    protected Group[] getRoleSets() throws LoginException {
        SimpleGroup group = new SimpleGroup("Roles");
        try {
            DB db = ConnectionProvider.getConnection(SERVIER_ADDR, username,
                    password, database).getDB(database);
            DBObject query = BasicDBObjectBuilder.start().push("_id")
                    .add("$in", userGroup).get();
            try (DBCursor cursor = db.getCollection(COLLECTION_USERGROUP).find(query)) {
                while (cursor.hasNext()) {
                    // User found in DB
                    BasicDBObject obj = (BasicDBObject) cursor.next();
                    BasicDBList dbList = (BasicDBList) obj.get(PERMISSIONS);
                    if (dbList != null) {
                        for (Object aDbList : dbList) {
                            group.addMember(new SimplePrincipal((String) aDbList));
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new LoginException("Failed to create group member for " + group);
        }
        return new Group[]{group};
    }

    private static final String COLLECTION_USER = "user";
    private static final String COLLECTION_USERGROUP = "usergroup";
    private static final String PASSWORD = "password";
    private static final String GROUP_IDS = "groupIds";

    private String doFindUser() {
        String userPassword = null;
        try {
            DB db = ConnectionProvider.getConnection(SERVIER_ADDR, username, password, database).getDB(database);
            BasicDBObject query = new BasicDBObject("name", getUsername());
            query.append("unlock", true);
            DBObject obj = db.getCollection(COLLECTION_USER).findOne(query);
            userPassword = (String) obj.get(PASSWORD);
            BasicDBList dbList = (BasicDBList) obj.get(GROUP_IDS);
            userGroup = new ArrayList<>();
            for (Object aDbList : dbList) {
                userGroup.add(new ObjectId((String) aDbList));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return userPassword;
    }
}