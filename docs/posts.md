
```mermaid
erDiagram
  PostInfo {
    int item_id
    int user_id
    int views
    int likes
    text data
    int comments
    datetime create_time
    datetime update_time
    int event_id
  }

  CommentInfo {
    int item_id
    int user_id
    int commented_item_id
    int likes
    int comments
    datetime create_time
    datetime update_time
    int event_id
  }

  LikeInfo {
    int like_id
    int user_id
    int like_time
    int liked_item_id
    int event_id
  }
```