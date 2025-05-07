# quiz/management/commands/load_movie_questions.py
from django.core.management.base import BaseCommand
from app1.models import Question

class Command(BaseCommand):
    help = 'Loads sample movie quiz questions into the database'

    def handle(self, *args, **kwargs):
        # Clear existing questions if needed
        # Question.objects.all().delete()
        
        # Sample movie questions
        questions = [
            {
                'question_text': 'Which movie won the Oscar for Best Picture in 2020?',
                'option_1': 'Parasite',
                'option_2': '1917',
                'option_3': 'Joker',
                'option_4': 'Once Upon a Time in Hollywood',
                'correct_answer': 'Parasite'
            },
            {
                'question_text': 'Who directed the movie "Inception"?',
                'option_1': 'Christopher Nolan',
                'option_2': 'Steven Spielberg',
                'option_3': 'Quentin Tarantino',
                'option_4': 'Martin Scorsese',
                'correct_answer': 'Christopher Nolan'
            },
            {
                'question_text': 'Which actor plays Iron Man in the Marvel Cinematic Universe?',
                'option_1': 'Robert Downey Jr.',
                'option_2': 'Chris Evans',
                'option_3': 'Chris Hemsworth',
                'option_4': 'Mark Ruffalo',
                'correct_answer': 'Robert Downey Jr.'
            },
            {
                'question_text': 'Which of these films is NOT directed by James Cameron?',
                'option_1': 'Jurassic Park',
                'option_2': 'Avatar',
                'option_3': 'Titanic',
                'option_4': 'The Terminator',
                'correct_answer': 'Jurassic Park'
            },
            {
                'question_text': 'Which movie features the character Luke Skywalker?',
                'option_1': 'Star Wars',
                'option_2': 'Star Trek',
                'option_3': 'Starship Troopers',
                'option_4': 'Stargate',
                'correct_answer': 'Star Wars'
            },
            {
                'question_text': 'Which actress won an Oscar for her role in "La La Land"?',
                'option_1': 'Emma Stone',
                'option_2': 'Jennifer Lawrence',
                'option_3': 'Natalie Portman',
                'option_4': 'Meryl Streep',
                'correct_answer': 'Emma Stone'
            },
            {
                'question_text': 'Which movie is based on a Stephen King novel?',
                'option_1': 'The Shawshank Redemption',
                'option_2': 'Pulp Fiction',
                'option_3': 'Goodfellas',
                'option_4': 'The Godfather',
                'correct_answer': 'The Shawshank Redemption'
            },
            {
                'question_text': 'Which movie features a character named "The Dude"?',
                'option_1': 'The Big Lebowski',
                'option_2': 'Fargo',
                'option_3': 'No Country for Old Men',
                'option_4': 'O Brother, Where Art Thou?',
                'correct_answer': 'The Big Lebowski'
            },
            {
                'question_text': 'What is the highest-grossing movie of all time (unadjusted for inflation)?',
                'option_1': 'Avatar',
                'option_2': 'Avengers: Endgame',
                'option_3': 'Titanic',
                'option_4': 'Star Wars: The Force Awakens',
                'correct_answer': 'Avatar'
            },
            {
                'question_text': 'Which movie won the first Academy Award for Best Animated Feature?',
                'option_1': 'Shrek',
                'option_2': 'Toy Story',
                'option_3': 'Monsters, Inc.',
                'option_4': 'The Lion King',
                'correct_answer': 'Shrek'
            }
        ]
        
        # Create questions
        for q_data in questions:
            Question.objects.create(**q_data)
            
        self.stdout.write(self.style.SUCCESS(f'Successfully loaded {len(questions)} movie questions'))