// static/js/watchlist.js
document.addEventListener('DOMContentLoaded', function() {
    // Handle watchlist button clicks
    document.querySelectorAll('.watchlist-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const movieId = this.dataset.movieId;
            const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
            
            fetch(`/app1/watchlist/toggle/${movieId}/`, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Update button text and class
                    if (data.in_watchlist) {
                        this.textContent = '-';
                        this.classList.add('in-watchlist');
                    } else {
                        this.textContent = '+';
                        this.classList.remove('in-watchlist');
                    }
                    
                    // Show notification
                    showNotification(data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An error occurred. Please try again.');
            });
        });
    });
    
    // Simple notification function
    function showNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Fade in
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Fade out and remove
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
});