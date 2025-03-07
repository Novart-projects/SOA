
```mermaid
erDiagram
  PostStats {
    int item_id
    int views_count
    int likes_count
    int comments_count
    datetime create_time
    datetime update_time
  }

  UserStats {
    int user_id
    int posts_count
    int comments_count
    int subscribers
    int subscriptions
    datetime last_seen
  }

  EventStats {
    int event_id
    string event_type
    int user_id
    int item_id
    datetime event_time
  }