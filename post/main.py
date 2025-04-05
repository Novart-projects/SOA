from concurrent import futures
import grpc
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base
import os
import posts_pb2
import posts_pb2_grpc

Base = declarative_base()

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    creator_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_private = Column(Boolean, default=False)
    tags = Column(String, default="")

DATABASE_URL = "sqlite:///./posts.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

class PostsServicer(posts_pb2_grpc.PostsServiceServicer):

    def CreatePost(self, request, context):
        db: Session = SessionLocal()
        try:
            new_post = Post(
                title=request.post.title,
                description=request.post.description,
                creator_id=request.post.creator_id,
                is_private=request.post.is_private,
                tags=",".join(request.post.tags)
            )
            db.add(new_post)
            db.commit()
            db.refresh(new_post)
            return posts_pb2.PostResponse(post=self._convert_to_grpc_post(new_post))
        finally:
            db.close()

    def DeletePost(self, request, context):
        db: Session = SessionLocal()
        try:
            post = db.query(Post).filter(Post.id == request.post_id, Post.creator_id == request.creator_id).first()
            if post:
                db.delete(post)
                db.commit()
                return posts_pb2.PostResponse(post=self._convert_to_grpc_post(post))
            else:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details('Post not found')
                return posts_pb2.PostResponse()
        finally:
            db.close()

    def UpdatePost(self, request, context):
        db: Session = SessionLocal()
        try:
            post = db.query(Post).filter(Post.id == request.post.id, Post.creator_id == request.creator_id).first()
            if post:
                post.title = request.post.title
                post.description = request.post.description
                post.is_private = request.post.is_private
                post.tags = ",".join(request.post.tags)
                post.updated_at = datetime.utcnow()
                db.commit()
                return posts_pb2.PostResponse(post=self._convert_to_grpc_post(post))
            else:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details('Post not found')
                return posts_pb2.PostResponse()
        finally:
            db.close()

    def GetPostById(self, request, context):
        db: Session = SessionLocal()
        try:
            post = db.query(Post).filter(
                Post.id == request.post_id,
                (Post.creator_id == request.creator_id) | (~Post.is_private)
            ).first()
            if post:
                return posts_pb2.PostResponse(post=self._convert_to_grpc_post(post))
            else:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details('Post not found')
                return posts_pb2.PostResponse()
        finally:
            db.close()

    def ListPosts(self, request, context):
        db: Session = SessionLocal()
        try:
            query = db.query(Post).filter(
                (Post.creator_id == request.creator_id) | (~Post.is_private)
            ).offset(request.page * request.page_size).limit(request.page_size).all()
            total_count = db.query(Post).count()
            return posts_pb2.ListPostsResponse(
                posts=[self._convert_to_grpc_post(p) for p in query],
                total_count=total_count
            )
        finally:
            db.close()

    def _convert_to_grpc_post(self, post):
        return posts_pb2.Post(
            id=str(post.id),
            title=post.title,
            description=post.description,
            creator_id=post.creator_id,
            created_at=post.created_at.isoformat(),
            updated_at=post.updated_at.isoformat(),
            is_private=post.is_private,
            tags=post.tags.split(",") if post.tags else []
        )

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    posts_pb2_grpc.add_PostsServiceServicer_to_server(PostsServicer(), server)
    port = os.environ.get('POST_SERVER_PORT', '8082')
    server.add_insecure_port("[::]:" + port)
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
