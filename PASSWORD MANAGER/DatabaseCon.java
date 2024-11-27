package PwdManager;
import java.sql.*;
public class DatabaseCon {

	public static void main(String[] args) throws ClassNotFoundException, SQLException {
		// TODO Auto-generated method stub
		Class.forName("com.mysql.jdbc.Driver");
		
		Connection con=DriverManager.getConnection("jdbc:mysql://localhost:3306//practice","root","Ramraya2308$");
        System.out.println("connection created");
	}

}
