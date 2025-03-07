```mermaid
erDiagram
  User {
    int user_id
    string gender
    int age
    string region
    datetime created_at
  }

  UserProfile {
    int profile_id
    int user_id
    string username
    string first_name
    string last_name
    date birthdate
  }
  USER_SETTINGS {
    int id
    int user_id
    string theme
    string language
    boolean notifications
  }
```