# Estate Management System

A simple role-based estate management system built with Flask and Tailwind CSS.

## Features

- Role-based access control (Admin, Agent, User)
- Property management (CRUD operations)
- Booking system with approval workflow
- Desktop Focused Design using Tailwind CSS
- User authentication and authorization
- Supabase PostgreSQL integration

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Supabase account and project
- Supabase storage bucket named "property-images"

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd estate-manager-app
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up Supabase:
   - Create a new project in Supabase
   - Go to Project Settings > Database
   - Find the Connection Info section
   - Copy the Connection String (URI)
   - Replace [YOUR-PASSWORD] with your database password

5. Create a `.env` file in the project root with the following content:
```
FLASK_APP=app
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=your-supabase-connection-string
SUPABASE_URL=your-supabase-url
SUPABASE_ANON_KEY=your-supabase-anon-key
```

6. Run the application:
```bash
python app.py
```

The script will:
- Initialize all tables
- Create a default admin user
- Start the Flask development server

The application will be available at `http://localhost:5000`

## Default Users

- Admin:
  - Email: admin@example.com
  - Password: admin123

## Project Structure

```
estate-manager/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── templates/         # HTML templates
│   ├── admin_dashboard.html
│   ├── agent_dashboard.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── maintenance_form.html
│   ├── maintenance_list.html
│   ├── message_detail.html
│   ├── message_form.html
│   ├── message_list.html
│   ├── payment_form.html
│   ├── payment_status.html
│   ├── property_detail.html
│   ├── property_form.html
│   ├── property_list.html
│   ├── register.html
│   ├── user_dashboard.html
└── .env               # Environment variables (create this file)
```


## Usage

1. Register as a new user (default role: user)
2. Admin can promote users to agents
3. Agents can create and manage properties
4. Users can browse properties and make booking requests
5. Agents can approve or reject booking requests
6. Admin has full access to manage users, properties, and bookings

## Security Features

- Password hashing using Werkzeug
- CSRF protection
- Role-based access control
- Input validation
- Secure session management
- Supabase PostgreSQL security

## Supabase Database Connection

The application uses Supabase PostgreSQL as its database. Your connection string in the `.env` file should look like this:

```
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres
```

You can find this in your Supabase project:
1. Go to Project Settings > Database
2. Look for "Connection Info" section
3. Copy the Connection String (URI)
4. Replace [YOUR-PASSWORD] with your database password

Note: Make sure to use the direct PostgreSQL connection string, not the Supabase API URL.

## Supabase Storage Setup

The application uses Supabase Storage for handling property images. Follow these steps to set up storage:

1. Create a storage bucket:
   - Go to Storage in your Supabase dashboard
   - Click "Create new bucket"
   - Name it `property-images`
   - Set it as public

2. Configure storage policies:
   - Click on the `property-images` bucket
   - Go to "Policies" tab
   - Add the following policies:

   For SELECT (view) operations:
   ```sql
   CREATE POLICY "Public Access"
   ON storage.objects FOR SELECT
   USING (bucket_id = 'property-images');
   ```

   For INSERT (upload) operations:
   ```sql
   CREATE POLICY "Authenticated users can upload"
   ON storage.objects FOR INSERT
   WITH CHECK (
     bucket_id = 'property-images'
   );
   ```

   For UPDATE operations:
   ```sql
   CREATE POLICY "Authenticated users can update own files"
   ON storage.objects FOR UPDATE
   USING (
     bucket_id = 'property-images'
   );
   ```

   For DELETE operations:
   ```sql
   CREATE POLICY "Authenticated users can delete own files"
   ON storage.objects FOR DELETE
   USING (
     bucket_id = 'property-images'
   );
   ```

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License.
