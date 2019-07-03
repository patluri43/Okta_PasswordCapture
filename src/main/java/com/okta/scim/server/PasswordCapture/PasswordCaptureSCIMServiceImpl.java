/**
 * Copyright Okta, Inc. 2013
 */
package com.okta.scim.server.PasswordCapture;

import com.okta.scim.server.capabilities.UserManagementCapabilities;
import com.okta.scim.server.exception.DuplicateGroupException;
import com.okta.scim.server.exception.EntityNotFoundException;
import com.okta.scim.server.exception.OnPremUserManagementException;
import com.okta.scim.server.service.SCIMOktaConstants;
import com.okta.scim.server.service.SCIMService;
import com.okta.scim.util.model.Name;
import com.okta.scim.util.model.PaginationProperties;
import com.okta.scim.util.model.SCIMFilter;
import com.okta.scim.util.model.SCIMGroup;
import com.okta.scim.util.model.SCIMGroupQueryResponse;
import com.okta.scim.util.model.SCIMUser;
import com.okta.scim.util.model.SCIMUserQueryResponse;
import org.codehaus.jackson.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This provides a working SCIM connector PasswordCapture where users and groups are kept in an database.
 * The sample database already has a large set of users, groups, and group memberships. The PasswordCapture shows how your connector can
 * work with an existing user database to only implement a subset of all the UM capabilities that Okta supports.
 * <p>
 * This connector assumes it is integrated with an App named <strong>onprem_password_capture_app</strong> that has one custom property,
 * <strong>uniqueid</strong>
 * <p>
 *
 * @author praven Atluri
 */
public class PasswordCaptureSCIMServiceImpl implements SCIMService {

    //Since this is just an PasswordCapture we won't always want to download every single user from the database

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordCaptureSCIMServiceImpl.class);

    //Using constants for the names of our App's custom properties
    private static final String CUSTOM_SCHEMA_PROPERTY_NAME_UNIQUE_ID = "uniqueid";

    //Our Okta AppName that this connector is going to be connected to
    private static final String APP_NAME = "opp";
    //Our Okta Universal Directory (UD) Schema Name that this connector is going to use for the custom properties
    private static final String UD_SCHEMA_NAME = "custom";
    //The custom SCIM extension where our App's custom properties will be found
    private static final String USER_CUSTOM_URN = SCIMOktaConstants.CUSTOM_URN_PREFIX + APP_NAME + SCIMOktaConstants.CUSTOM_URN_SUFFIX + UD_SCHEMA_NAME;

    private static final Set<String> ALL_VALID_CUSTOM_SCHEMA_PROPERTY_NAMES = new HashSet<String>();


    //Database connection information, these properties are set via the Spring dispatcher-servlet.xml file
    private String serverName;
    private int serverPort;
    private String databaseName;
    private String userName;
    private String password;
    private String connectionString;
    private String databaseType;
    private String databaseConnectionURL;



    /**
     * Builds and validates the Database connection properties. It is called after Spring creates an instance of the class.
     *
     * @throws Exception
     */
    @PostConstruct
    public void afterCreation() throws Exception {
        try {
            if (databaseType.equalsIgnoreCase("sqlserver")){
                Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
            } else {
                Class.forName("org.drizzle.jdbc.DrizzleDriver").newInstance();
            }

        } catch (Exception ex) {
            LOGGER.error("Unable to find the org.drizzle.jdbc.DrizzleDriver class: " + ex.getMessage(), ex);
            throw ex;
        }

        if (databaseType.equalsIgnoreCase("sqlserver")){
            connectionString = databaseConnectionURL;

        }else {

            connectionString = String.format("jdbc:mysql:thin://%s:%d/%s",
                    this.serverName, this.serverPort, this.databaseName);

        }


        //test that everything works
        Connection conn = getDatabaseConnection();
        cleanupConnection(null, null, conn);

        //we use this Set during our SCIM filter evaluation to make sure all filter queries that get created only
        //contains the known custom fields and not just any custom field name from the extension passed in through the query string

        ALL_VALID_CUSTOM_SCHEMA_PROPERTY_NAMES.add(CUSTOM_SCHEMA_PROPERTY_NAME_UNIQUE_ID);

    }

    /**
     * This method creates a user. All the standard attributes of the SCIM User can be retrieved by using the
     * getters on the SCIMStandardUser member of the SCIMUser object.
     * <p>
     * If there are custom schemas in the SCIMUser input, you can retrieve them by providing the name of the
     * custom property. 
     * <p><em>Example:</em> <code>SCIMUser.getStringCustomProperty("schemaName", "customFieldName")</code>, for a
     * string type property.</p>
     * <p>
     * This method is invoked when a POST is made to /Users with a SCIM payload representing a user
     * to create.
     * <p>
     * <strong>NOTE:</strong> While the user's group memberships are populated by Okta, according to the SCIM Spec
     * (http://www.simplecloud.info/specs/draft-scim-core-schema-01.html#anchor4), that information should be
     * considered read-only. Group memberships should only be updated through calls to createGroup or updateGroup.
     *
     * @param user A SCIMUser representation of the SCIM String payload sent by the SCIM client.
     * @return The created SCIMUser.
     * @throws OnPremUserManagementException
     */
    @Override
    public SCIMUser createUser(SCIMUser user) throws OnPremUserManagementException {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        Connection conn = null;

        try {

            String unique_oktaUserID = getImmutableId(user);

            //get a new connection and start a new transaction
            conn = getDatabaseConnection();
            conn.setAutoCommit(false);

            if (checkIfUserExists(unique_oktaUserID)) {
                String query = "UPDATE okta_users set first_name=?, last_name=?, user_name=?, is_active=? WHERE userid = ?";
                //build statement
                stmt = conn.prepareStatement(query);

                stmt.setString(1, user.getName().getFirstName());
                stmt.setString(2, user.getName().getLastName());
                stmt.setString(3, user.getUserName());
                stmt.setBoolean(4, user.isActive());
                stmt.setString(5, unique_oktaUserID);
            } else {
                //Start the INSERT query
                String query = "INSERT INTO okta_users (userid, first_name, last_name, user_name, is_active) VALUES (?, ?, ?, ?, ?)";

                //create the statement and make sure our auto-incremented ID is returned
                stmt = conn.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);

                //populate our prepared statement with all the parameters
                stmt.setString(1, unique_oktaUserID);
                stmt.setString(2, user.getName().getFirstName());
                stmt.setString(3, user.getName().getLastName());
                stmt.setString(4, user.getUserName());
                stmt.setBoolean(5, user.isActive());
            }

            int affectedRows = stmt.executeUpdate();
            if (affectedRows != 1) {
                throw new OnPremUserManagementException("CREATE_USER_INSERT_FAILED", "Creating user failed, expected 1 row affected but " + affectedRows + " rows affected.");
            }


            //commit the transaction
            conn.commit();

            //return the most up to date copy of the user
            user.setId(unique_oktaUserID);


        } catch (SQLException ex) {
             handleSQLException("createUser", ex, "CREATE_USER_INSERT_FAILED_EXCEPTION", conn);

        } finally {
            cleanupConnection(stmt, rs, conn);
        }

        return user;
    }


    /**
     * This method updates a user.
     * <p>
     * This method is invoked when a PUT is made to <code>/Users/{id}</code> with the SCIM payload representing a user to
     * update.
     * <p>
     * <strong>NOTE:</strong> While the user's group memberships is populated by Okta, according to the SCIM Spec
     * (http://www.simplecloud.info/specs/draft-scim-core-schema-01.html#anchor4), that information should be
     * considered read-only. Group memberships should only be updated through calls to <code>createGroup</code> or <code>updateGroup</code>.
     *
     * @param id   The id of the SCIM user.
     * @param user A SCIMUser representation of the SCIM String payload sent by the SCIM client.
     * @return The updated SCIMUser.
     * @throws OnPremUserManagementException
     */
    @Override
    public SCIMUser updateUser(String id, SCIMUser user) throws OnPremUserManagementException, EntityNotFoundException {
        //validate that the user already exists

        String unique_oktaUserID = getImmutableId(user);

        if (!unique_oktaUserID.equalsIgnoreCase(user.getId())) {
            throw new OnPremUserManagementException("UPDATE_USER_ID_MISMATCH", "Modifying the user id is not allowed.");
        }

        PreparedStatement stmt = null;
        ResultSet rs = null;
        Connection conn = null;


        try {
            //UPDATE the user record with everything passed in
            //get a new connection and start a new transaction
            conn = getDatabaseConnection();
            conn.setAutoCommit(false);


            if (user.isActive() && user.getPassword() != null ) {


                System.out.println("printing password::"+user.getPassword());

                if (!EncryptionUtil.areKeysPresent()) {
                    // Method generates a pair of keys using the RSA algorithm and stores it
                    // in their respective files
                    EncryptionUtil.generateKey();
                }

                String query = "UPDATE okta_users set first_name=?, last_name=?, user_name=?, password = ?, is_active=?  WHERE userid = ?";

                //build statement
                stmt = conn.prepareStatement(query);

                byte[] cypherText = EncryptionUtil.encrypt(user.getPassword());


                stmt.setString(1, user.getName().getFirstName());
                stmt.setString(2, user.getName().getLastName());
                stmt.setString(3, user.getUserName());
                stmt.setBytes(4, cypherText);
                stmt.setBoolean(5, user.isActive());
                stmt.setString(6, unique_oktaUserID);

            } else if (user.isActive() && user.getPassword() == null){
                String query = "UPDATE okta_users set first_name=?, last_name=?, user_name=?, is_active=? WHERE userid = ?";
                //build statement
                stmt = conn.prepareStatement(query);

                stmt.setString(1, user.getName().getFirstName());
                stmt.setString(2, user.getName().getLastName());
                stmt.setString(3, user.getUserName());
                stmt.setBoolean(4, user.isActive());
                stmt.setString(5, unique_oktaUserID);
            } else if (!user.isActive()){
                String query = "UPDATE okta_users set is_active=? WHERE userid = ?";
                //build statement
                stmt = conn.prepareStatement(query);
                stmt.setBoolean(1, user.isActive());
                stmt.setString(2, unique_oktaUserID);
            } else {
                throw new  OnPremUserManagementException("Check the SCIM request from OKTA", "Modifying the user id is not allowed.");
            }

            int affectedRows = stmt.executeUpdate();
            if (affectedRows != 1) {
                throw new OnPremUserManagementException("UPDATE_USER_FAILED", "Updating user " + id + " failed, expected 1 row affected but " + affectedRows + " rows affected.");
            }

            //NOTE: user.groupsGroups() is considered READ-ONLY according to the SCIM Spec
            // http://www.simplecloud.info/specs/draft-scim-core-schema-01.html#anchor4
            // Okta will serialize the user's group membership information for your reference but you should not
            // update the group membership from it. That should only happen through calls to createGroup or updateGroup

            //commit and save
            conn.commit();
        } catch (SQLException ex) {
            handleSQLException("updateUser", ex, "UPDATE_USER_FAILED_EXCEPTION", conn);
        }  finally {
            cleanupConnection(stmt, rs, conn);
        }

        //return the most up to date user
        user.setId(unique_oktaUserID);
        return user;
    }

    /**
     * Get all the users.
     * <p>
     * This method is invoked when a GET is made to /Users.
     * To support pagination, so that the client and the server are not overwhelmed, this method supports querying based on a start index and the
     * maximum number of results expected by the client. The implementation is responsible for maintaining indices for the SCIM Users.
     *
     * @param pageProperties The pagination properties.
     * @param filter         The filter
     * @return The response from the server, which contains a list of  users along with the total number of results, the start index, and the items per page.
     * @throws com.okta.scim.server.exception.OnPremUserManagementException
     *
     * NOTE:: This method is returning Mock Response as the OPP agent invokes this method before creating a new user
     *
     */
    @Override
    public SCIMUserQueryResponse getUsers(PaginationProperties pageProperties, SCIMFilter filter) throws OnPremUserManagementException {
        SCIMUserQueryResponse response = new SCIMUserQueryResponse();
        List<SCIMUser> users = new ArrayList<SCIMUser>();
        SCIMUser user = new SCIMUser();
        user.setUserName(filter.getFilterValue());
        users.add(user);
        response.setScimUsers(users);
        if (filter != null) {
            return response;
        } else {
            throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
        }
    }

    /**
     * Get a particular user.
     * <p>
     * This method is invoked when a GET is made to /Users/{id}
     *
     * @param id the Id of the SCIM User
     * @return the user corresponding to the id
     * @throws
     *
     */
    @Override
    public SCIMUser getUser(String id) throws EntityNotFoundException {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        Connection conn = null;

        SCIMUser user = new SCIMUser();
        user.setId(id);


        try {

            conn = getDatabaseConnection();

            String query = "SELECT user_name,password,is_active FROM okta_users WHERE userid=?";

            //build statement
            stmt = conn.prepareStatement(query);

            stmt.setString(1, id);

            rs = stmt.executeQuery();


            if (rs.next()){
                user.setUserName(rs.getString(1));
                user.setPassword(EncryptionUtil.decrypt(rs.getBytes(2)));
                user.setActive(rs.getBoolean(3));
            }


        } catch (SQLException ex) {
            handleSQLException("getUserById", ex, "GET_USER_BY_ID exception", null);

        } finally {
            cleanupConnection(stmt, rs, conn);

        }

        return user;

    }

    /**
     * Get all the groups.
     * <p>
     * This method is invoked when a GET is made to /Groups
     * In order to support pagination (So that the client and the server) are not overwhelmed, this method supports querying based on a start index and the
     * maximum number of results expected by the client. The implementation is responsible for maintaining indices for the SCIM groups.
     *
     * @param pageProperties @see com.okta.scim.util.model.PaginationProperties An object holding the properties needed for pagination - startindex and the count.
     * @return SCIMGroupQueryResponse the response from the server containing the total number of results, start index and the items per page along with a list of groups
     * @throws com.okta.scim.server.exception.OnPremUserManagementException
     *
     */
    @Override
    public SCIMGroupQueryResponse getGroups(PaginationProperties pageProperties) throws OnPremUserManagementException {
        throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Get a particular group.
     * <p>
     * This method is invoked when a GET is made to <code>/Groups/{id}</code>.
     *
     * @param //id The id of the SCIM group.
     * @return The group corresponding to the id.
     * @throws com.okta.scim.server.exception.OnPremUserManagementException
     *
     */
    @Override
    public SCIMGroup getGroup(String string) throws OnPremUserManagementException, EntityNotFoundException {
        throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * This method creates a group. All the standard attributes of the SCIM group can be retrieved by using the
     * getters on the SCIMStandardGroup member of the SCIMGroup object.
     * <p>
     * If there are custom schemas in the SCIMGroup input, you can retrieve them by providing the name of the
     * custom property. 
     * <p><em>Example:</em> <code>SCIMGroup.getCustomProperty("schemaName", "customFieldName"))</code>.</p>
     * <p>
     * This method is invoked when a POST is made to /Groups with a SCIM payload representing a group
     * to be created.
     *
     * @param //group A SCIMGroup representation of the SCIM String payload sent by the SCIM client.
     * @return The created SCIMGroup
     * @throws com.okta.scim.server.exception.OnPremUserManagementException
     *
     */
    @Override
    public SCIMGroup createGroup(SCIMGroup scimg) throws OnPremUserManagementException, DuplicateGroupException {
        throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * This method updates a group.
     * <p>
     * This method is invoked when a PUT is made to <code>/Groups/{id}</code> with the SCIM payload representing a group to
     * update.
     *
     * @param //id The id of the SCIM group.
     * @param //group SCIMGroup representation of the SCIM String payload sent by the SCIM client.
     * @return The updated SCIMGroup.
     * @throws com.okta.scim.server.exception.OnPremUserManagementException
     *
     */
    @Override
    public SCIMGroup updateGroup(String string, SCIMGroup scimg) throws OnPremUserManagementException, EntityNotFoundException {
        throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
    }


    /**
     * Delete a particular group.
     * <p>
     * This method is invoked when a DELETE is made to <code>/Groups/{id}</code>.
     *
     * @param //id id of the SCIM group.
     * @throws OnPremUserManagementException
     */
    @Override
    public void deleteGroup(String string) throws OnPremUserManagementException, EntityNotFoundException {
        throw new UnsupportedOperationException("Not supported."); //To change body of generated methods, choose Tools | Templates.
    }
    /**
     * Get all the Okta User Management capabilities that this SCIM Service has implemented.
     * <p>
     * This method is invoked when a GET is made to /ServiceProviderConfigs. It is called only when you are testing
     * or modifying your connector configuration from the Okta Application instance UM UI. If you change the return values
     * at a later time please retest and resave your connector settings to have your new return values respected.
     * <p>
     * These User Management capabilities help customize the UI features available to your app instance and tells Okta
     * all the possible commands that can be sent to your connector.
     *
     * @return all the implemented User Management capabilities.
     */
    @Override
    public UserManagementCapabilities[] getImplementedUserManagementCapabilities() {
        return new UserManagementCapabilities[]{
                UserManagementCapabilities.PUSH_NEW_USERS,
                UserManagementCapabilities.PUSH_PROFILE_UPDATES,

                //because of our sample database schema, we have no active/inactive or password columns
                //so we will tell Okta that we don't support the below capabilities since these capabilities all
                //relate to either the active/inactive state of a user, or updating the user's password
                UserManagementCapabilities.PUSH_PASSWORD_UPDATES,
                UserManagementCapabilities.PUSH_USER_DEACTIVATION
        };
    }

    /*
    Start private database implementation
     */

    /**
     * Get the server name.
     *
     * @return The server name.
     */
    public String getServerName() {
        return serverName;
    }

    /**
     * Set the server name.
     *
     * @param serverName The server name to set.
     */
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    /**
     * Get the server port.
     *
     * @return The server port.
     */
    public int getServerPort() {
        return serverPort;
    }

    /**
     * Set the server port.
     *
     * @param serverPort The integer value of the server port to set.
     */
    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    /**
     * Get the database name.
     *
     * @return The database name.
     */
    public String getDatabaseName() {
        return databaseName;
    }

    /**
     * Set the database name.
     *
     * @param databaseName The database name to set.
     */
    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    /**
     * Get the user name.
     *
     * @return The user name.
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Set the user name.
     *
     * @param userName The user name to set.
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Get the password.
     *
     * @return The password.
     */
    public String getPassword() {
        return password;
    }
    /**
     * Set the password.
     *
     * @param password The value of the password to set.
     */

    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Get the databaseType
     *
     * @return the databaseType
     */

    public String getDatabaseType() {
        return databaseType;
    }

    /**
     * set the database Type sqlserver/mysql
     *
     * @param databaseType the value of database type to set
     */
    public void setDatabaseType(String databaseType){
        this.databaseType = databaseType;
    }


    /**
     * Get the databaseType
     *
     * @return the DatabaseConnectionURL
     */

    public String getDatabaseConnectionURL() {
        return databaseConnectionURL;
    }

    /**
     * set the database Type sqlserver/mysql
     *
     * @param databaseConnectionURL the value of database type to set
     */
    public void setDatabaseConnectionURL(String databaseConnectionURL){
        this.databaseConnectionURL = databaseConnectionURL;
    }

    /**
     * Generate the SQL query from the EQUALITY SCIM filter
     *
     * @param conn             the sql connection
     * @param filter           SCIM filter
     * @param initialUserIndex first user (0 based) record to return
     * @param maxUsers         max number of users to return
     * @return sql query for the users
     */
    private PreparedStatement getUsersQueryByEqualityFilter(Connection conn, SCIMFilter filter, long initialUserIndex, int maxUsers) throws SQLException {
        //for consistency, make sure we always return the users in the same order no matter what query
        List<Object> values = new ArrayList<Object>();
        String query = "SELECT userid FROM okta_users WHERE  ORDER BY last_name, first_name, userid LIMIT " + initialUserIndex + ", " + maxUsers;
        PreparedStatement stmt = conn.prepareStatement(query);
        for (int i = 0; i < values.size(); i++) {
            stmt.setObject(i + 1, values.get(i));
        }
        return stmt;
    }


    /*
    * Encrypt the string using Sha256 cert
     */

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
    /**
     * Here is one PasswordCapture of what might need to be done when your database does not generate the unique record ids for you.
     * It will throw a DuplicateGroupException when the group name is not going to be unique. Because of the schema we are
     * working with we cannot just create a UUID/GUID and use that as our unique value.
     * <p/>
     * This is NOT a perfect PasswordCapture, it is not thread safe or guaranteed to work if you have multiple connectors or applications
     * talking to the same database.
     *
     * @param //displayName group name
     * @return new unique group id to use
     */
    /**
     * Check if user is active in Database
     *
     * @param id the user id
     * @return the user
     */
    private boolean checkIfUserExists(String id) {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        Connection conn = getDatabaseConnection();

        try {
            String query = "select e.is_active FROM okta_users AS e WHERE e.userid = ?";
            stmt = conn.prepareStatement(query);
            stmt.setString(1, id);

            rs = stmt.executeQuery();

            if (rs.next()) {
                return true;
            }

        } catch (SQLException ex) {
            handleSQLException("getUserById", ex, "GET_USER_BY_ID_EXCEPTION", null);
        } finally {
            cleanupConnection(stmt, rs, conn);
        }
        return false;
    }



    /**
     * get the value of immutableId from user request
     *
     * @param user
     * @return the String Value of id attribute
     */
    private String getImmutableId(SCIMUser user){

        //Get the custom properties map (SchemaName -> JsonNode)
        Map<String, JsonNode> customPropertiesMap = user.getCustomPropertiesMap();


        //in this PasswordCapture we expect our custom extension URN to be present
        if (customPropertiesMap == null || !customPropertiesMap.containsKey(USER_CUSTOM_URN)) {
            //you could decide to throw an exception if it is not there, and uncomment the following line
            throw new OnPremUserManagementException("MISSING_CUSTOM_PROPERTIES", "user missing the expected custom extension: " + USER_CUSTOM_URN);
        } else {
            //Get the JsonNode having all the custom properties for this schema
            JsonNode customNode = customPropertiesMap.get(USER_CUSTOM_URN);

            //getting the values directly from the customNode containing all of our custom schema extension properties.
            // See the updateUser method below for a different way of getting to the values from your custom schema extension
            return customNode.get(CUSTOM_SCHEMA_PROPERTY_NAME_UNIQUE_ID).asText();
        }

    }

    private Connection getDatabaseConnection() throws OnPremUserManagementException {
        Connection conn;
        try {

            if (databaseType.equalsIgnoreCase("sqlserver")){
                conn = DriverManager.getConnection(connectionString);
            } else {
                conn = DriverManager.getConnection(connectionString, this.userName, this.password);
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to connect to " + connectionString + " as " + this.userName + " - " + ex.getMessage(), ex);
            throw new OnPremUserManagementException("DB_CONNECTION_FAILED", ex.getMessage(), ex);
        }
        return conn;
    }

    private void cleanupConnection(Statement stmt, ResultSet rs, Connection conn) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException sqlEx) {
                LOGGER.error("Unable cleanup and close the result set", sqlEx);
            }
        }

        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException sqlEx) {
                LOGGER.error("Unable cleanup and close the statement", sqlEx);
            }
        }

        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException sqlEx) {
                LOGGER.error("Unable cleanup and close the db connection", sqlEx);
            }
        }
    }

    private void handleSQLException(String methodName, SQLException ex, String customErrorCode, Connection conn) throws OnPremUserManagementException {
        // log any errors
        LOGGER.error(methodName + " Failed - SQLException: " + ex.getMessage() +
                "\r\nSQLState: " + ex.getSQLState() +
                "\r\nVendorError: " + ex.getErrorCode(), ex);

        if (conn != null) {
            try {
                conn.rollback();
            } catch (SQLException e) {
                LOGGER.error("Rollback failed", e);
            }
        }

        throw new OnPremUserManagementException(customErrorCode, ex.getMessage(), ex);
    }
}
