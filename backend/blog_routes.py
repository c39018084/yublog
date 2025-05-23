"""
Blog Routes for YuBlog
CRUD operations for blog posts with security validation
"""

from datetime import datetime, timedelta
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import ValidationError
from sqlalchemy import or_, desc, func

from app import app, db, limiter, log_audit_event, generate_slug
from app import User, Post, PostSchema

# Blog Post Routes
@app.route('/api/posts', methods=['GET'])
def get_posts():
    """Get published blog posts with pagination and search"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = min(request.args.get('limit', 10, type=int), 50)  # Max 50 posts per page
        search = request.args.get('search', '')
        tag = request.args.get('tag', '')
        author = request.args.get('author', '')
        
        # Build query for published posts
        query = Post.query.filter_by(published=True)
        
        # Add search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Post.title.ilike(search_term),
                    Post.content.ilike(search_term),
                    Post.excerpt.ilike(search_term)
                )
            )
        
        # Add author filter
        if author:
            user = User.query.filter(
                or_(User.username == author, User.display_name.ilike(f"%{author}%"))
            ).first()
            if user:
                query = query.filter_by(author_id=user.id)
        
        # Add tag filter (this would require a join with post_tags table)
        # For now, we'll implement a simple content search for tags
        if tag:
            query = query.filter(Post.content.ilike(f"%{tag}%"))
        
        # Order by creation date (newest first)
        query = query.order_by(desc(Post.created_at))
        
        # Get total count for pagination
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        posts = query.offset(offset).limit(limit).all()
        
        # Calculate pagination info
        total_pages = (total + limit - 1) // limit
        
        return jsonify({
            'posts': [
                {
                    'id': post.id,
                    'title': post.title,
                    'slug': post.slug,
                    'excerpt': post.excerpt or post.content[:200] + '...' if len(post.content) > 200 else post.content,
                    'author': {
                        'username': post.author.username,
                        'displayName': post.author.display_name
                    },
                    'createdAt': post.created_at.isoformat(),
                    'updatedAt': post.updated_at.isoformat()
                }
                for post in posts
            ],
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': total_pages,
                'hasNext': page < total_pages,
                'hasPrev': page > 1
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch posts'}), 500

@app.route('/api/posts/<slug>', methods=['GET'])
def get_post_by_slug(slug):
    """Get a single blog post by slug"""
    try:
        post = Post.query.filter_by(slug=slug, published=True).first()
        
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        return jsonify({
            'post': {
                'id': post.id,
                'title': post.title,
                'slug': post.slug,
                'content': post.content,
                'excerpt': post.excerpt,
                'author': {
                    'username': post.author.username,
                    'displayName': post.author.display_name
                },
                'createdAt': post.created_at.isoformat(),
                'updatedAt': post.updated_at.isoformat(),
                'published': post.published
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch post'}), 500

@app.route('/api/posts', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def create_post():
    """Create a new blog post"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate input
        schema = PostSchema()
        validated_data = schema.load(data)
        
        # Generate slug from title
        base_slug = generate_slug(validated_data['title'])
        slug = base_slug
        counter = 1
        
        # Ensure slug uniqueness
        while Post.query.filter_by(slug=slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        # Generate excerpt if not provided
        excerpt = validated_data.get('excerpt')
        if not excerpt:
            content = validated_data['content']
            # Remove HTML tags for excerpt
            import re
            clean_content = re.sub('<[^<]+?>', '', content)
            excerpt = clean_content[:200] + '...' if len(clean_content) > 200 else clean_content
        
        # Create post
        post = Post(
            title=validated_data['title'],
            slug=slug,
            content=validated_data['content'],
            excerpt=excerpt,
            author_id=user_id,
            published=validated_data.get('published', False)
        )
        
        db.session.add(post)
        db.session.commit()
        
        log_audit_event(user_id, 'create_post', True,
                      resource_type='post', resource_id=post.id)
        
        return jsonify({
            'success': True,
            'post': {
                'id': post.id,
                'title': post.title,
                'slug': post.slug,
                'content': post.content,
                'excerpt': post.excerpt,
                'published': post.published,
                'createdAt': post.created_at.isoformat()
            }
        }), 201
        
    except ValidationError as e:
        log_audit_event(get_jwt_identity(), 'create_post', False,
                      details={'validation_errors': e.messages})
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'create_post', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to create post'}), 500

@app.route('/api/posts/<post_id>', methods=['PUT'])
@jwt_required()
@limiter.limit("20 per hour")
def update_post(post_id):
    """Update an existing blog post"""
    try:
        user_id = get_jwt_identity()
        
        # Find post
        post = Post.query.filter_by(id=post_id, author_id=user_id).first()
        
        if not post:
            log_audit_event(user_id, 'update_post', False,
                          details={'error': 'Post not found'})
            return jsonify({'error': 'Post not found or no permission'}), 404
        
        data = request.get_json()
        
        # Validate input
        schema = PostSchema()
        validated_data = schema.load(data)
        
        # Update title and regenerate slug if title changed
        if validated_data['title'] != post.title:
            base_slug = generate_slug(validated_data['title'])
            slug = base_slug
            counter = 1
            
            # Ensure slug uniqueness (excluding current post)
            while Post.query.filter(Post.slug == slug, Post.id != post.id).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            post.slug = slug
        
        # Update fields
        post.title = validated_data['title']
        post.content = validated_data['content']
        
        # Update excerpt
        if 'excerpt' in data:
            post.excerpt = data['excerpt']
        else:
            # Auto-generate excerpt from content
            import re
            clean_content = re.sub('<[^<]+?>', '', validated_data['content'])
            post.excerpt = clean_content[:200] + '...' if len(clean_content) > 200 else clean_content
        
        if 'published' in validated_data:
            post.published = validated_data['published']
        
        post.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        log_audit_event(user_id, 'update_post', True,
                      resource_type='post', resource_id=post.id)
        
        return jsonify({
            'success': True,
            'post': {
                'id': post.id,
                'title': post.title,
                'slug': post.slug,
                'content': post.content,
                'excerpt': post.excerpt,
                'published': post.published,
                'updatedAt': post.updated_at.isoformat()
            }
        })
        
    except ValidationError as e:
        log_audit_event(get_jwt_identity(), 'update_post', False,
                      details={'validation_errors': e.messages})
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'update_post', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to update post'}), 500

@app.route('/api/posts/<post_id>', methods=['DELETE'])
@jwt_required()
@limiter.limit("10 per hour")
def delete_post(post_id):
    """Delete a blog post"""
    try:
        user_id = get_jwt_identity()
        
        # Find post
        post = Post.query.filter_by(id=post_id, author_id=user_id).first()
        
        if not post:
            log_audit_event(user_id, 'delete_post', False,
                          details={'error': 'Post not found'})
            return jsonify({'error': 'Post not found or no permission'}), 404
        
        # Store post details for audit log
        post_details = {
            'title': post.title,
            'slug': post.slug
        }
        
        db.session.delete(post)
        db.session.commit()
        
        log_audit_event(user_id, 'delete_post', True,
                      resource_type='post', resource_id=post_id,
                      details=post_details)
        
        return jsonify({
            'success': True,
            'message': 'Post deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'delete_post', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to delete post'}), 500

@app.route('/api/posts/<post_id>/publish', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def toggle_post_publish(post_id):
    """Toggle post publication status"""
    try:
        user_id = get_jwt_identity()
        
        # Find post
        post = Post.query.filter_by(id=post_id, author_id=user_id).first()
        
        if not post:
            return jsonify({'error': 'Post not found or no permission'}), 404
        
        # Toggle published status
        post.published = not post.published
        post.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        action = 'publish_post' if post.published else 'unpublish_post'
        log_audit_event(user_id, action, True,
                      resource_type='post', resource_id=post.id)
        
        return jsonify({
            'success': True,
            'published': post.published,
            'message': f'Post {"published" if post.published else "unpublished"} successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'publish_post', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to update post status'}), 500

# Author-specific routes
@app.route('/api/my/posts', methods=['GET'])
@jwt_required()
def get_my_posts():
    """Get current user's posts (including drafts)"""
    try:
        user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        limit = min(request.args.get('limit', 10, type=int), 50)
        status = request.args.get('status', 'all')  # all, published, draft
        
        # Build query
        query = Post.query.filter_by(author_id=user_id)
        
        # Filter by status
        if status == 'published':
            query = query.filter_by(published=True)
        elif status == 'draft':
            query = query.filter_by(published=False)
        
        # Order by updated date (newest first)
        query = query.order_by(desc(Post.updated_at))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        posts = query.offset(offset).limit(limit).all()
        
        # Calculate pagination info
        total_pages = (total + limit - 1) // limit
        
        return jsonify({
            'posts': [
                {
                    'id': post.id,
                    'title': post.title,
                    'slug': post.slug,
                    'excerpt': post.excerpt,
                    'published': post.published,
                    'createdAt': post.created_at.isoformat(),
                    'updatedAt': post.updated_at.isoformat()
                }
                for post in posts
            ],
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': total_pages,
                'hasNext': page < total_pages,
                'hasPrev': page > 1
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch posts'}), 500

@app.route('/api/my/posts/<post_id>', methods=['GET'])
@jwt_required()
def get_my_post(post_id):
    """Get a specific post by the current user (including drafts)"""
    try:
        user_id = get_jwt_identity()
        post = Post.query.filter_by(id=post_id, author_id=user_id).first()
        
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        return jsonify({
            'post': {
                'id': post.id,
                'title': post.title,
                'slug': post.slug,
                'content': post.content,
                'excerpt': post.excerpt,
                'published': post.published,
                'createdAt': post.created_at.isoformat(),
                'updatedAt': post.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch post'}), 500

# Statistics routes
@app.route('/api/stats/posts', methods=['GET'])
@jwt_required()
def get_post_stats():
    """Get post statistics for the current user"""
    try:
        user_id = get_jwt_identity()
        
        # Get counts
        total_posts = Post.query.filter_by(author_id=user_id).count()
        published_posts = Post.query.filter_by(author_id=user_id, published=True).count()
        draft_posts = total_posts - published_posts
        
        # Get recent activity (posts created in last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_posts = Post.query.filter(
            Post.author_id == user_id,
            Post.created_at >= thirty_days_ago
        ).count()
        
        return jsonify({
            'total': total_posts,
            'published': published_posts,
            'drafts': draft_posts,
            'recentActivity': recent_posts
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch statistics'}), 500

# Search and filter helpers
@app.route('/api/posts/search', methods=['GET'])
def search_posts():
    """Advanced search for published posts"""
    try:
        query_text = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        limit = min(request.args.get('limit', 10, type=int), 50)
        
        if not query_text:
            return jsonify({'posts': [], 'pagination': {'total': 0}})
        
        # Build search query
        search_term = f"%{query_text}%"
        query = Post.query.filter(
            Post.published == True,
            or_(
                Post.title.ilike(search_term),
                Post.content.ilike(search_term),
                Post.excerpt.ilike(search_term)
            )
        ).order_by(desc(Post.created_at))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        posts = query.offset(offset).limit(limit).all()
        
        return jsonify({
            'posts': [
                {
                    'id': post.id,
                    'title': post.title,
                    'slug': post.slug,
                    'excerpt': post.excerpt,
                    'author': {
                        'username': post.author.username,
                        'displayName': post.author.display_name
                    },
                    'createdAt': post.created_at.isoformat(),
                    'relevance': 1.0  # Could implement actual relevance scoring
                }
                for post in posts
            ],
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'query': query_text
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Search failed'}), 500 