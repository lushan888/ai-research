"""
Secure database module with parameterized queries.
Prevents first-order and second-order SQL injection.
"""
import sqlite3
import os
from typing import Optional, List, Tuple, Any


def get_db_path() -> str:
    """Get database file path."""
    return os.path.join(os.path.dirname(__file__), 'data', 'app.db')


def get_connection() -> sqlite3.Connection:
    """Get database connection with row factory."""
    os.makedirs(os.path.dirname(get_db_path()), exist_ok=True)
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def execute_query(query: str, params: Tuple[Any, ...] = ()) -> List[sqlite3.Row]:
    """
    Execute a parameterized query safely.
    Never concatenate user input into query strings!
    
    Args:
        query: SQL query with ? placeholders
        params: Tuple of parameter values
    
    Returns:
        List of result rows
    """
    conn = get_connection()
    try:
        cursor = conn.execute(query, params)
        conn.commit()
        return cursor.fetchall()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def export_comments_to_csv() -> str:
    """
    Export all comments to CSV using parameterized queries.
    Prevents second-order SQL injection by never concatenating
    user data into SQL statements.
    """
    rows = execute_query(
        "SELECT id, username, comment, created_at FROM comments ORDER BY created_at DESC"
    )
    
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Comment', 'Created At'])
    
    for row in rows:
        writer.writerow([
            row['id'],
            row['username'],
            row['comment'],
            row['created_at']
        ])
    
    return output.getvalue()


def add_comment(username: str, comment: str) -> int:
    """
    Add a comment using parameterized query.
    
    Args:
        username: The commenter's username
        comment: The comment text
    
    Returns:
        The new comment ID
    """
    rows = execute_query(
        "INSERT INTO comments (username, comment) VALUES (?, ?) RETURNING id",
        (username, comment)
    )
    return rows[0]['id'] if rows else -1
